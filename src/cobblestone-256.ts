/**
 * Cobblestone-256: the c2sp.org/chunked-encryption high-level API over
 * AEAD_AES_256_GCM. Keys are 32 bytes and MUST be uniformly random.
 */

import { AES_256_GCM } from "./internal/derive.js";
import {
  type CobblestoneInstance,
  type CobblestoneOptions,
  makeCobblestone,
} from "./cobblestone.js";
import type { ByteRangeSource, DecryptingReader } from "./internal/engine.js";

const c: CobblestoneInstance = makeCobblestone(AES_256_GCM);

/** Required key length, in bytes, for every function in this module. */
export const KEY_SIZE = 32;

/**
 * Encrypts `plaintext` in one call. Throws/rejects {@link InvalidKeyError}
 * if `key.length !== KEY_SIZE`.
 */
export const encrypt: typeof c.encrypt = c.encrypt;

/**
 * Decrypts `ciphertext` produced by {@link encrypt} or
 * {@link EncryptionStream}. Rejects {@link InvalidKeyError} for a wrong key
 * length, {@link TruncationError} if the ciphertext is too short,
 * {@link CommitmentMismatchError} if the key or context doesn't match, or
 * {@link AuthenticationError} if any chunk fails to authenticate.
 */
export const decrypt: typeof c.decrypt = c.decrypt;

/**
 * A {@link TransformStream} that encrypts written plaintext chunks into
 * framed ciphertext chunks (header first, then sealed chunks). The
 * constructor throws {@link InvalidKeyError} synchronously if
 * `key.length !== KEY_SIZE`.
 */
export const EncryptionStream: typeof c.EncryptionStream = c.EncryptionStream;

/**
 * A {@link TransformStream} that decrypts framed ciphertext chunks back
 * into plaintext. The constructor throws {@link InvalidKeyError}
 * synchronously if `key.length !== KEY_SIZE`; once fed data, it rejects
 * {@link TruncationError}, {@link CommitmentMismatchError}, or
 * {@link AuthenticationError} per the same rules as {@link decrypt}.
 */
export const DecryptionStream: typeof c.DecryptionStream = c.DecryptionStream;

/**
 * Opens a random-access {@link DecryptingReader} over `source`. Rejects
 * {@link InvalidKeyError} for a wrong key length (checked before any I/O),
 * {@link InvalidSizeError} if the source is too short or malformed, or
 * {@link CommitmentMismatchError} if the key or context doesn't match. The
 * final chunk is authenticated eagerly, so a successful open does not
 * guarantee every earlier chunk will also authenticate on read.
 */
export const openDecryptingReader: typeof c.openDecryptingReader = c.openDecryptingReader;

/**
 * Computes the plaintext length for a ciphertext of `n` bytes. Throws
 * {@link InvalidSizeError} if `n` isn't a valid framed-ciphertext length.
 */
export const plaintextSize: typeof c.plaintextSize = c.plaintextSize;

/**
 * Computes the ciphertext length for a plaintext of `n` bytes. Throws
 * {@link InvalidSizeError} if `n` is out of range.
 */
export const ciphertextSize: typeof c.ciphertextSize = c.ciphertextSize;

export * from "./errors.js";
export type { ByteRangeSource, CobblestoneOptions, DecryptingReader };
