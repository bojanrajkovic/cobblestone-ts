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
import { checkAead, decryptTransformer, encryptTransformer } from "./internal/engine.js";

export {
  AuthenticationError,
  CobblestoneError,
  CommitmentMismatchError,
  CounterOverflowError,
  InvalidKeyError,
  InvalidSizeError,
  TruncationError,
} from "./errors.js";
export type { Aead };
export { aesGcm } from "./internal/aes-gcm.js";

export const CHUNK_SIZE = 16384;
export const CHUNK_OVERHEAD = 16;

export class RawEncryptionStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(aead: Aead, baseNonce: Uint8Array) {
    checkAead(aead, baseNonce);
    super(encryptTransformer(aead, baseNonce));
  }
}

export class RawDecryptionStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(aead: Aead, baseNonce: Uint8Array) {
    checkAead(aead, baseNonce);
    super(decryptTransformer(aead, baseNonce));
  }
}

export { encryptedChunkCount, plaintextSize } from "./internal/engine.js";
