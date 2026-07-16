import { AuthenticationError, InvalidKeyError } from "../errors.js";
import { concat } from "./bytes.js";

export interface Aead {
  readonly nonceSize: number;
  readonly overhead: 16;
  seal(nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  open(nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
}

// node:crypto's synchronous AES-GCM avoids WebCrypto's async dispatch overhead —
// benchmarked ~3-6x faster on Node/Bun at the spec's 16 KiB chunk size, since both
// have real native sync bindings. Deno and workerd are excluded: their node:crypto
// is a shim over the same underlying WebCrypto primitives and measured slower, not
// faster, there. See github.com/bojanrajkovic/cobblestone-ts/issues/5.
// COBBLESTONE_FORCE_WEBCRYPTO=1 forces the WebCrypto path — the escape hatch if
// the fast path ever misbehaves, and how CI covers both paths on Node/Bun.
export const nodeCryptoFastPathActive: boolean =
  typeof process !== "undefined" &&
  typeof process.versions?.node === "string" &&
  !("Deno" in globalThis) &&
  (globalThis as { navigator?: { userAgent?: string } }).navigator?.userAgent !==
    "Cloudflare-Workers" &&
  process.env["COBBLESTONE_FORCE_WEBCRYPTO"] !== "1";

// Cached across calls (module evaluation is memoized by the runtime regardless,
// but re-resolving the specifier still walks the ESM loader every time — measured
// ~13% of samples in resolveSync/getOrCreateModuleJobAfterResolve on a hot path).
// Still a dynamic import, never static — browser/Deno/workerd bundlers must never
// see a reachable node: reference.
let nodeCryptoPromise: Promise<typeof import("node:crypto")> | undefined;
export const nodeCrypto: () => Promise<typeof import("node:crypto")> = () =>
  (nodeCryptoPromise ??= import("node:crypto"));

export async function aesGcm(key: Uint8Array): Promise<Aead> {
  if (key.length !== 16 && key.length !== 32) {
    throw new InvalidKeyError(`key must be 16 or 32 bytes, got ${key.length}`);
  }

  if (nodeCryptoFastPathActive) {
    const { createCipheriv, createDecipheriv, createSecretKey } = await nodeCrypto();
    const algo = key.length === 16 ? "aes-128-gcm" : "aes-256-gcm";
    // Snapshot the key now, not read it lazily from the closure on every call:
    // WebCrypto's importKey() copies the key bytes immediately below, so seal/open
    // must be equally immune to the caller mutating `key` after aesGcm() returns —
    // this is reachable via the public hazmat API, not just internal callers.
    const keyObject = createSecretKey(key);

    return {
      nonceSize: 12,
      overhead: 16,
      async seal(nonce, plaintext) {
        const cipher = createCipheriv(algo, keyObject, nonce);
        const body = cipher.update(plaintext);
        cipher.final();
        return concat(body, cipher.getAuthTag());
      },
      async open(nonce, ciphertext) {
        try {
          const tag = ciphertext.subarray(ciphertext.length - 16);
          const body = ciphertext.subarray(0, ciphertext.length - 16);
          const decipher = createDecipheriv(algo, keyObject, nonce);
          decipher.setAuthTag(tag);
          const opened = decipher.update(body);
          decipher.final();
          return new Uint8Array(opened);
        } catch {
          // Never leak the native crypto error — callers only see our error types.
          throw new AuthenticationError("AES-GCM authentication failed");
        }
      },
    };
  }

  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);

  return {
    nonceSize: 12,
    overhead: 16,
    async seal(nonce, plaintext) {
      const sealed = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        cryptoKey,
        plaintext,
      );
      return new Uint8Array(sealed);
    },
    async open(nonce, ciphertext) {
      try {
        const opened = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: nonce },
          cryptoKey,
          ciphertext,
        );
        return new Uint8Array(opened);
      } catch {
        // Never leak the DOMException — callers only see our error types.
        throw new AuthenticationError("AES-GCM authentication failed");
      }
    },
  };
}
