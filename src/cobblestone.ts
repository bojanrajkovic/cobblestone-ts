// Internal factory for the high-level Cobblestone API. Instantiated once per
// AEAD size by cobblestone-128.ts and cobblestone-256.ts — not exported from
// the package directly.

import { aesGcm } from "./internal/aes-gcm.js";
import { concat, constantTimeEqual, utf8 } from "./internal/bytes.js";
import { type AeadDescriptor, deriveMessageParams } from "./internal/derive.js";
import {
  CHUNK_OVERHEAD,
  CHUNK_SIZE,
  decryptTransformer,
  encryptTransformer,
  MAX_CHUNKS,
  normalizeSource,
  openRawReader,
  plaintextSize as chunkPlaintextSize,
  sectionSource,
} from "./internal/engine.js";
import type { ByteRangeSource, DecryptingReader } from "./internal/engine.js";
import {
  CommitmentMismatchError,
  InvalidKeyError,
  InvalidSizeError,
  TruncationError,
} from "./errors.js";

const HEADER_SIZE = 56;
const SALT_SIZE = 24;

/** Options accepted by every high-level encrypt/decrypt entry point. */
export interface CobblestoneOptions {
  /** Application-defined string bound into key derivation — not sent as AAD. Defaults to empty. */
  context?: string | Uint8Array;
}

/**
 * The API surface produced by {@link makeCobblestone} for one AEAD size.
 * cobblestone-128.ts and cobblestone-256.ts each instantiate one of these
 * and re-export its members individually with size-specific docs.
 */
export interface CobblestoneInstance {
  /** Required key length, in bytes, for every member below. */
  readonly KEY_SIZE: number;
  /** Encrypts `plaintext` in one call. Rejects {@link InvalidKeyError} for a wrong key length. */
  encrypt(key: Uint8Array, plaintext: Uint8Array, opts?: CobblestoneOptions): Promise<Uint8Array>;
  /**
   * Decrypts a ciphertext produced by `encrypt` or `EncryptionStream`.
   * Rejects {@link InvalidKeyError}, {@link TruncationError},
   * {@link CommitmentMismatchError}, or {@link AuthenticationError}.
   */
  decrypt(key: Uint8Array, ciphertext: Uint8Array, opts?: CobblestoneOptions): Promise<Uint8Array>;
  /**
   * A {@link TransformStream} that frames and encrypts written plaintext.
   * Throws {@link InvalidKeyError} synchronously for a wrong key length.
   */
  readonly EncryptionStream: new (
    key: Uint8Array,
    opts?: CobblestoneOptions,
  ) => TransformStream<Uint8Array, Uint8Array>;
  /**
   * A {@link TransformStream} that decrypts a framed ciphertext stream.
   * Throws {@link InvalidKeyError} synchronously for a wrong key length;
   * once fed data, rejects per `decrypt`'s rules.
   */
  readonly DecryptionStream: new (
    key: Uint8Array,
    opts?: CobblestoneOptions,
  ) => TransformStream<Uint8Array, Uint8Array>;
  /**
   * Opens a random-access {@link DecryptingReader} over `source`. Rejects
   * {@link InvalidKeyError}, {@link InvalidSizeError},
   * {@link TruncationError}, or {@link CommitmentMismatchError}.
   */
  openDecryptingReader(
    key: Uint8Array,
    source: Blob | ByteRangeSource,
    opts?: CobblestoneOptions,
  ): Promise<DecryptingReader>;
  /** Computes the plaintext length for a ciphertext of `n` bytes. Throws {@link InvalidSizeError} if invalid. */
  plaintextSize(n: number): number;
  /** Computes the ciphertext length for a plaintext of `n` bytes. Throws {@link InvalidSizeError} if out of range. */
  ciphertextSize(n: number): number;
}

function normalizeContext(context: string | Uint8Array | undefined): Uint8Array {
  if (context === undefined) return new Uint8Array(0);
  return typeof context === "string" ? utf8(context) : context;
}

// A minimal TransformStreamDefaultController stand-in that writes straight
// into a pre-sized output buffer instead of enqueueing into a real stream.
// One-shot encrypt/decrypt drive encryptTransformer/decryptTransformer
// directly through this — same tested chunk-framing/error logic, without
// constructing a TransformStream or collecting+concatenating its output.
function sinkController(
  sink: (chunk: Uint8Array) => void,
): TransformStreamDefaultController<Uint8Array> {
  return { enqueue: sink } as TransformStreamDefaultController<Uint8Array>;
}

export function makeCobblestone(d: AeadDescriptor): CobblestoneInstance {
  class EncryptionStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(key: Uint8Array, opts?: CobblestoneOptions) {
      if (key.length !== d.keySize) {
        throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
      }
      const context = normalizeContext(opts?.context);
      let inner: ReturnType<typeof encryptTransformer> | undefined;

      super({
        async start(controller) {
          const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
          const { aeadKey, baseNonce, commitment } = await deriveMessageParams(
            d,
            key,
            salt,
            context,
          );
          const aead = await aesGcm(aeadKey);
          controller.enqueue(concat(salt, commitment));
          inner = encryptTransformer(aead, baseNonce);
        },
        transform(chunk, controller) {
          // start() always resolves before transform/flush run (Web Streams
          // spec gates writes on startPromise) — inner is always set here.
          return inner!.transform(chunk, controller);
        },
        flush(controller) {
          return inner!.flush(controller);
        },
      });
    }
  }

  class DecryptionStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(key: Uint8Array, opts?: CobblestoneOptions) {
      if (key.length !== d.keySize) {
        throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
      }
      const context = normalizeContext(opts?.context);
      let header: Uint8Array[] = [];
      let headerLength = 0;
      let inner: ReturnType<typeof decryptTransformer> | undefined;

      super({
        async transform(chunk, controller) {
          if (inner === undefined) {
            header.push(chunk);
            headerLength += chunk.length;
            if (headerLength < HEADER_SIZE) return;

            const joined = concat(...header);
            header = [];
            const salt = joined.subarray(0, SALT_SIZE);
            const commitment = joined.subarray(SALT_SIZE, HEADER_SIZE);
            const surplus = joined.subarray(HEADER_SIZE);

            const derived = await deriveMessageParams(d, key, salt, context);
            if (!constantTimeEqual(derived.commitment, commitment)) {
              throw new CommitmentMismatchError("derived commitment does not match header");
            }
            const aead = await aesGcm(derived.aeadKey);
            inner = decryptTransformer(aead, derived.baseNonce);
            if (surplus.length > 0) await inner.transform(surplus, controller);
            return;
          }
          await inner.transform(chunk, controller);
        },
        async flush(controller) {
          if (inner === undefined) {
            throw new TruncationError(`truncated header: ${headerLength} of ${HEADER_SIZE} bytes`);
          }
          await inner.flush(controller);
        },
      });
    }
  }

  async function encryptOneShot(
    key: Uint8Array,
    plaintext: Uint8Array,
    opts?: CobblestoneOptions,
  ): Promise<Uint8Array> {
    if (key.length !== d.keySize) {
      throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
    }
    const context = normalizeContext(opts?.context);

    const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const { aeadKey, baseNonce, commitment } = await deriveMessageParams(d, key, salt, context);
    const aead = await aesGcm(aeadKey);

    const out = new Uint8Array(ciphertextSize(plaintext.length));
    out.set(salt, 0);
    out.set(commitment, SALT_SIZE);

    let offset = HEADER_SIZE;
    const controller = sinkController((chunk) => {
      out.set(chunk, offset);
      offset += chunk.length;
    });

    const transformer = encryptTransformer(aead, baseNonce);
    await transformer.transform(plaintext, controller);
    await transformer.flush(controller);

    return out;
  }

  async function decryptOneShot(
    key: Uint8Array,
    ciphertext: Uint8Array,
    opts?: CobblestoneOptions,
  ): Promise<Uint8Array> {
    if (key.length !== d.keySize) {
      throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
    }
    if (ciphertext.length < HEADER_SIZE) {
      throw new TruncationError(`truncated header: ${ciphertext.length} of ${HEADER_SIZE} bytes`);
    }
    const context = normalizeContext(opts?.context);

    const salt = ciphertext.subarray(0, SALT_SIZE);
    const commitment = ciphertext.subarray(SALT_SIZE, HEADER_SIZE);
    const body = ciphertext.subarray(HEADER_SIZE);

    const derived = await deriveMessageParams(d, key, salt, context);
    if (!constantTimeEqual(derived.commitment, commitment)) {
      throw new CommitmentMismatchError("derived commitment does not match header");
    }
    const aead = await aesGcm(derived.aeadKey);

    // Upper bound, not the exact size: the encrypted body always strips at
    // least one CHUNK_OVERHEAD-sized tag, so this can only over-allocate.
    // decryptTransformer's own transform/flush stay the sole source of
    // truth for truncation/auth/overflow errors — deliberately not
    // precomputed via plaintextSize(), which validates structural size
    // upfront and would throw InvalidSizeError instead of TruncationError
    // for a malformed body (see the reader's own InvalidSizeError remap
    // in vectors.test.ts — one-shot decrypt must keep the stream's error
    // classes, not the reader's).
    const out = new Uint8Array(body.length);
    let offset = 0;
    const controller = sinkController((chunk) => {
      out.set(chunk, offset);
      offset += chunk.length;
    });

    const transformer = decryptTransformer(aead, derived.baseNonce);
    await transformer.transform(body, controller);
    await transformer.flush(controller);

    return out.subarray(0, offset);
  }

  async function openDecryptingReader(
    key: Uint8Array,
    source: Blob | ByteRangeSource,
    opts?: CobblestoneOptions,
  ): Promise<DecryptingReader> {
    if (key.length !== d.keySize) {
      throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
    }
    const context = normalizeContext(opts?.context);
    const src = normalizeSource(source);
    if (src.size < HEADER_SIZE) {
      throw new InvalidSizeError(
        `source size ${src.size} is smaller than the ${HEADER_SIZE}-byte header`,
      );
    }

    const header = await src.readAt(0, HEADER_SIZE);
    if (header.length !== HEADER_SIZE) {
      throw new TruncationError(
        `short header read: expected ${HEADER_SIZE} bytes, got ${header.length}`,
      );
    }
    const salt = header.subarray(0, SALT_SIZE);
    const commitment = header.subarray(SALT_SIZE, HEADER_SIZE);

    const derived = await deriveMessageParams(d, key, salt, context);
    if (!constantTimeEqual(derived.commitment, commitment)) {
      throw new CommitmentMismatchError("derived commitment does not match header");
    }
    const aead = await aesGcm(derived.aeadKey);
    return openRawReader(aead, derived.baseNonce, sectionSource(src, HEADER_SIZE));
  }

  function plaintextSize(n: number): number {
    if (!Number.isSafeInteger(n) || n < 0) {
      throw new InvalidSizeError(`ciphertext size must be a non-negative safe integer, got ${n}`);
    }
    if (n < HEADER_SIZE) {
      throw new InvalidSizeError(
        `ciphertext size ${n} is smaller than the ${HEADER_SIZE}-byte header`,
      );
    }
    return chunkPlaintextSize(n - HEADER_SIZE);
  }

  function ciphertextSize(n: number): number {
    const maxPlaintext = MAX_CHUNKS * CHUNK_SIZE - 1;
    if (!Number.isSafeInteger(n) || n < 0 || n > maxPlaintext) {
      throw new InvalidSizeError(
        `plaintext size must be a safe integer in [0, ${maxPlaintext}], got ${n}`,
      );
    }
    return HEADER_SIZE + n + (Math.floor(n / CHUNK_SIZE) + 1) * CHUNK_OVERHEAD;
  }

  return {
    KEY_SIZE: d.keySize,
    encrypt: encryptOneShot,
    decrypt: decryptOneShot,
    EncryptionStream,
    DecryptionStream,
    openDecryptingReader,
    plaintextSize,
    ciphertextSize,
  };
}
