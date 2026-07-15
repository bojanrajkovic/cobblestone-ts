import { InvalidKeyError, InvalidSizeError } from "../errors.js";
import type { Aead } from "./aes-gcm.js";

export const CHUNK_SIZE = 16384;
export const CHUNK_OVERHEAD = 16;
const ENC_CHUNK_SIZE = CHUNK_SIZE + CHUNK_OVERHEAD;
const MAX_CHUNKS = 2 ** 38;

export function checkAead(aead: Aead, baseNonce: Uint8Array): void {
  if (aead.overhead !== 16) {
    throw new InvalidKeyError(`aead overhead must be 16, got ${aead.overhead}`);
  }
  if (aead.nonceSize < 12 || aead.nonceSize > 32) {
    throw new InvalidKeyError(`aead nonce size must be 12..32 bytes, got ${aead.nonceSize}`);
  }
  if (baseNonce.length !== aead.nonceSize) {
    throw new InvalidKeyError(
      `base nonce must be ${aead.nonceSize} bytes, got ${baseNonce.length}`,
    );
  }
}

// Returns a copy of baseNonce with chunkIndex XORed into its last 5 bytes,
// big-endian. chunkIndex is assumed < 2**38 — callers enforce the cap.
export function nonceFor(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
  const out = baseNonce.slice();
  const len = out.length;
  const hi = Math.floor(chunkIndex / 2 ** 32) & 0xff; // >32-bit part — division, not JS's 32-bit `>>>`
  const lo = chunkIndex >>> 0;
  out[len - 5] = (out[len - 5] ?? 0) ^ hi;
  out[len - 4] = (out[len - 4] ?? 0) ^ ((lo >>> 24) & 0xff);
  out[len - 3] = (out[len - 3] ?? 0) ^ ((lo >>> 16) & 0xff);
  out[len - 2] = (out[len - 2] ?? 0) ^ ((lo >>> 8) & 0xff);
  out[len - 1] = (out[len - 1] ?? 0) ^ (lo & 0xff);
  return out;
}

export function encryptedChunkCount(encryptedSize: number): number {
  if (!Number.isSafeInteger(encryptedSize) || encryptedSize < 0) {
    throw new InvalidSizeError(
      `encrypted size must be a non-negative safe integer, got ${encryptedSize}`,
    );
  }

  const chunks = Math.ceil(encryptedSize / ENC_CHUNK_SIZE);
  const pt = encryptedSize - chunks * CHUNK_OVERHEAD;
  if (Math.floor(pt / CHUNK_SIZE) + 1 !== chunks) {
    throw new InvalidSizeError(
      `encrypted size ${encryptedSize} is not a valid chunked-ciphertext length`,
    );
  }
  if (chunks > MAX_CHUNKS) {
    throw new InvalidSizeError(`encrypted size ${encryptedSize} exceeds ${MAX_CHUNKS} chunks`);
  }

  return chunks;
}

export function plaintextSize(encryptedSize: number): number {
  return encryptedSize - encryptedChunkCount(encryptedSize) * CHUNK_OVERHEAD;
}
