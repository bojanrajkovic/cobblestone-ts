/**
 * Raw chunked-encryption mode, per the c2sp.org/chunked-encryption appendix.
 *
 * Raw mode has no 56-byte header and no key commitment: the ciphertext is
 * just concatenated sealed chunks. The key and base nonce MUST be uniformly
 * random and unique per message — this module does not derive or manage
 * either for you.
 *
 * This is a low-level building block for protocol implementers. Applications
 * almost certainly want the high-level API instead.
 */

import type { Aead } from "./internal/aes-gcm.js";
import type { ByteRangeSource, DecryptingReader } from "./internal/engine.js";
import {
  checkAead,
  decryptTransformer,
  encryptTransformer,
  normalizeSource,
  openRawReader,
} from "./internal/engine.js";

export {
  AuthenticationError,
  CobblestoneError,
  CommitmentMismatchError,
  CounterOverflowError,
  InvalidKeyError,
  InvalidSizeError,
  TruncationError,
} from "./errors.js";
export type { Aead, ByteRangeSource, DecryptingReader };
export { aesGcm } from "./internal/aes-gcm.js";

/** Plaintext bytes per chunk before sealing. */
export const CHUNK_SIZE = 16384;
/** AEAD tag bytes added to each sealed chunk. */
export const CHUNK_OVERHEAD = 16;

/**
 * A {@link TransformStream} that seals written plaintext into raw
 * fixed-size AEAD chunks using an already-derived `aead`/`baseNonce`. The
 * constructor throws {@link InvalidKeyError} synchronously if `aead`'s
 * overhead/nonce size or `baseNonce`'s length are invalid.
 */
export class RawEncryptionStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(aead: Aead, baseNonce: Uint8Array) {
    checkAead(aead, baseNonce);
    super(encryptTransformer(aead, baseNonce));
  }
}

/**
 * A {@link TransformStream} that opens raw fixed-size AEAD chunks back into
 * plaintext using an already-derived `aead`/`baseNonce`. The constructor
 * throws {@link InvalidKeyError} synchronously for an invalid `aead`/
 * `baseNonce`; once fed data, it rejects {@link TruncationError} or
 * {@link AuthenticationError}.
 */
export class RawDecryptionStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(aead: Aead, baseNonce: Uint8Array) {
    checkAead(aead, baseNonce);
    super(decryptTransformer(aead, baseNonce));
  }
}

export { encryptedChunkCount, plaintextSize } from "./internal/engine.js";

/**
 * Opens a random-access {@link DecryptingReader} over raw chunked
 * ciphertext, using an already-derived `aead`/`baseNonce`. Rejects
 * {@link InvalidKeyError} for an invalid `aead`/`baseNonce`,
 * {@link InvalidSizeError} if `source` is malformed, {@link TruncationError}
 * for a short read, or {@link AuthenticationError} if the final chunk fails
 * to authenticate. The final chunk is authenticated eagerly, so a
 * successful open does not guarantee every earlier chunk will also
 * authenticate on read.
 */
export async function openRawDecryptingReader(
  aead: Aead,
  baseNonce: Uint8Array,
  source: Blob | ByteRangeSource,
): Promise<DecryptingReader> {
  checkAead(aead, baseNonce);
  return openRawReader(aead, baseNonce, normalizeSource(source));
}
