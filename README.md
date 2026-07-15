# cobblestone-ts

[![CI](https://github.com/bojanrajkovic/cobblestone-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/bojanrajkovic/cobblestone-ts/actions/workflows/ci.yml)

TypeScript implementation of the [C2SP chunked-encryption scheme](https://c2sp.org/chunked-encryption), ported from the Go reference implementation [filippo.io/cobblestone](https://github.com/FiloSottile/cobblestone). It ships two instantiations — Cobblestone-128 (SHA-512 + AES-128-GCM, the spec-recommended default) and Cobblestone-256 (SHA-512 + AES-256-GCM, for compliance requirements that mandate 256-bit keys). ESM-only, zero runtime dependencies, all cryptography through WebCrypto (`crypto.subtle`) — no native bindings and no `node:` imports, so the API surface is universal (browsers, Deno, Bun, edge runtimes). CI runs the full test suite on Node ≥24, Bun, Deno, Chromium, WebKit, Firefox, and workerd (the Cloudflare Workers runtime).

## Install

```sh
pnpm add cobblestone-ts
# or
npm install cobblestone-ts
```

## Quickstart

Three runnable examples. `KEY_SIZE`, `encrypt`, `decrypt`, `EncryptionStream`, and `openDecryptingReader` all come from the package's default export (Cobblestone-128); import from `cobblestone-ts/cobblestone-256` instead if you need 256-bit keys.

**One-shot encrypt/decrypt**, with an optional `context` binding the ciphertext to an application-defined string:

```ts
import { encrypt, decrypt, KEY_SIZE } from "cobblestone-ts";

const key = crypto.getRandomValues(new Uint8Array(KEY_SIZE));
const plaintext = new TextEncoder().encode("attack at dawn");

const ciphertext = await encrypt(key, plaintext, { context: "example.com/messages" });
const decrypted = await decrypt(key, ciphertext, { context: "example.com/messages" });
```

**Streaming a `File`/`Blob` through `EncryptionStream`:**

```ts
import { EncryptionStream, KEY_SIZE } from "cobblestone-ts";

const key = crypto.getRandomValues(new Uint8Array(KEY_SIZE));
declare const file: Blob; // e.g. from <input type="file"> or a fetch() response

const encryptedStream = file.stream().pipeThrough(new EncryptionStream(key));
for await (const chunk of encryptedStream) {
  // write chunk to disk, upload it, etc.
}
```

**Random-access reads with `openDecryptingReader`**, without decrypting the whole message:

```ts
import { openDecryptingReader, KEY_SIZE } from "cobblestone-ts";

declare const key: Uint8Array; // KEY_SIZE bytes
declare const ciphertext: Blob; // a full ciphertext, e.g. a File

const reader = await openDecryptingReader(key, ciphertext);
const middle = await reader.readAt(20_000, 100);
```

All three examples above were run against the built package (`pnpm build`, then imported from `./dist/...` rather than the package name shown here) to confirm they work as written.

## API tour

| Entry point                      | Contents                                                                                                        |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `cobblestone-ts`                 | Re-export of `cobblestone-ts/cobblestone-128`                                                                   |
| `cobblestone-ts/cobblestone-128` | Cobblestone-128: SHA-512 + AES-128-GCM, 16-byte keys — pick this unless a compliance requirement says otherwise |
| `cobblestone-ts/cobblestone-256` | Cobblestone-256: SHA-512 + AES-256-GCM, 32-byte keys                                                            |
| `cobblestone-ts/hazmat`          | Raw chunked-encryption primitives — no header, no key commitment, no key derivation                             |
| `cobblestone-ts/errors`          | The `CobblestoneError` hierarchy, importable without pulling in any crypto                                      |

Each of `cobblestone-128` and `cobblestone-256` exports the same shape, sized for its own key length:

- `KEY_SIZE` — required key length in bytes (16 or 32)
- `encrypt(key, plaintext, opts?)` — one-shot encrypt, returns `Promise<Uint8Array>`
- `decrypt(key, ciphertext, opts?)` — one-shot decrypt, returns `Promise<Uint8Array>`
- `EncryptionStream` — a `TransformStream<Uint8Array, Uint8Array>` that frames and encrypts as it's written
- `DecryptionStream` — a `TransformStream<Uint8Array, Uint8Array>` that decrypts a framed ciphertext stream
- `openDecryptingReader(key, source, opts?)` — opens a random-access decrypting reader over a `Blob` or a `ByteRangeSource`
- `plaintextSize(n)` / `ciphertextSize(n)` — size math for a given ciphertext/plaintext length, without touching the data

`opts` is `{ context?: string | Uint8Array }` on every function/constructor above — see [Security notes](#security-notes) for what `context` does.

## Errors

Every error this package throws extends `CobblestoneError`. Synchronous constructors (`new EncryptionStream(...)`, `new DecryptionStream(...)`) throw directly; every `async` function rejects instead.

| Class                     | Meaning                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `CobblestoneError`        | Base class for every error below                                                                         |
| `InvalidKeyError`         | The key isn't the right length for the instantiation, or an AEAD/key precondition failed                 |
| `CommitmentMismatchError` | The derived commitment doesn't match the ciphertext header — wrong key or wrong `context`                |
| `AuthenticationError`     | An AEAD chunk failed to authenticate — corrupted or tampered ciphertext                                  |
| `TruncationError`         | The ciphertext or header ended before a complete header/chunk was read                                   |
| `InvalidSizeError`        | A size argument is out of range — e.g. `plaintextSize`/`ciphertextSize` input, or a reader offset/length |
| `CounterOverflowError`    | The per-message chunk counter exceeded 2^38 — the message is too large for one key/context               |

## Hazmat

`cobblestone-ts/hazmat` exposes the raw chunked-encryption mode from the spec's appendix: fixed-size AEAD chunks with no 56-byte header and no key commitment. The caller supplies an already-derived AEAD key and base nonce directly and is responsible for making both uniformly random and unique per message — this module does no key derivation or management on your behalf.

This is a low-level building block for protocol implementers who need to embed chunked encryption in a larger format. You almost certainly want the high-level API (`cobblestone-ts`, `cobblestone-ts/cobblestone-128`, or `cobblestone-ts/cobblestone-256`) instead.

## Security notes

- **The input key MUST be uniformly random** — output from a CSPRNG or a KDF, never a password. If you're starting from a password, derive a uniformly random key first with something like argon2, scrypt, or PBKDF2; that derivation is the caller's responsibility and out of scope for this package.
- **`context` binds application data into key derivation**, not into the ciphertext as AAD. Use it to scope a key to a purpose (a filename, a protocol name, a tenant ID) so the same input key can't be reused to decrypt a message meant for a different context.
- **Maximum message size is 4 PiB − 1 byte.** Overhead is a fixed 56 bytes (header) plus a marginal ~0.1% (16-byte AEAD tag per 16 KiB chunk).
- The chunk-counter nonce space bounds how many messages a single key/context pair can safely encrypt at a given message size:

  | Max message size | Max message count |
  | ---------------- | ----------------- |
  | 32 MiB           | 2^55              |
  | 1 GiB            | 2^45              |
  | 32 GiB           | 2^35              |
  | 1 TiB            | 2^25              |
  | 32 TiB           | 32768             |
  | 1 PiB            | 32                |
  | 4 PiB            | 2                 |

See the spec's [security analysis](https://c2sp.org/chunked-encryption#security-analysis) for the full derivation of these bounds.

## Interop & provenance

Cobblestone-128 ciphertexts produced by this package decrypt with [filippo.io/cobblestone](https://github.com/FiloSottile/cobblestone) and vice versa. Cobblestone-256 is implemented here per the spec but currently has no high-level API in the Go reference implementation, so cross-implementation interop for it is TS-side only until upstream ships one.

Test vectors (`testdata/vectors_aes_128_gcm.json`, `testdata/vectors_aes_256_gcm.json`) are copied byte-identical from [FiloSottile/cobblestone](https://github.com/FiloSottile/cobblestone) at commit `83fdae03308e2c38c739eb3a61d8cde2202ba46a`; the vector files self-identify their generator at commit `5203de0d5c09d83d3a4ea7a99748c8245c39fcaa`.

Published npm releases use [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC, no long-lived npm token) and are built with `--provenance`. Verify a published version's provenance with:

```sh
npm audit signatures
```

## License

BSD-3-Clause. Copyright 2022 Filippo Valsorda, Copyright 2026 Bojan Rajkovic. The scheme, the reference implementation, and the test vectors are Filippo Valsorda's; see [LICENSE](./LICENSE) for the full text.
