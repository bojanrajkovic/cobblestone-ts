import {
  CounterOverflowError,
  InvalidKeyError,
  InvalidSizeError,
  TruncationError,
} from "../errors.js";
import type { Aead } from "./aes-gcm.js";

// Structural stand-in for the WHATWG Transformer<I,O> interface. @types/node
// only puts TransformStream (and its controller) in global scope; the
// Transformer parameter type itself lives behind "node:stream/web", and
// src/ stays off node:* imports even for types. This shape is what
// TransformStream's constructor structurally accepts.
interface Transformer<I, O> {
  transform(chunk: I, controller: TransformStreamDefaultController<O>): Promise<void>;
  flush(controller: TransformStreamDefaultController<O>): Promise<void>;
}

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

export function encryptTransformer(
  aead: Aead,
  baseNonce: Uint8Array,
): Transformer<Uint8Array, Uint8Array> {
  const buf = new Uint8Array(CHUNK_SIZE);
  let filled = 0;
  let chunkIndex = 0;

  async function sealBuffered(
    controller: TransformStreamDefaultController<Uint8Array>,
    length: number,
  ): Promise<void> {
    if (chunkIndex >= MAX_CHUNKS) {
      throw new CounterOverflowError(`chunk index ${chunkIndex} exceeds ${MAX_CHUNKS}`);
    }
    const sealed = await aead.seal(nonceFor(baseNonce, chunkIndex), buf.subarray(0, length));
    controller.enqueue(sealed);
    chunkIndex++;
  }

  return {
    async transform(chunk, controller) {
      let offset = 0;
      while (offset < chunk.length) {
        const take = Math.min(CHUNK_SIZE - filled, chunk.length - offset);
        buf.set(chunk.subarray(offset, offset + take), filled);
        filled += take;
        offset += take;
        if (filled === CHUNK_SIZE) {
          await sealBuffered(controller, CHUNK_SIZE);
          filled = 0;
        }
      }
    },
    async flush(controller) {
      // The final chunk is always emitted, even if it's empty — this is
      // what lets a decryptor distinguish a clean end from truncation.
      await sealBuffered(controller, filled);
    },
  };
}

export function decryptTransformer(
  aead: Aead,
  baseNonce: Uint8Array,
): Transformer<Uint8Array, Uint8Array> {
  const pending: Uint8Array[] = [];
  let pendingLength = 0;
  let chunkIndex = 0;

  function push(chunk: Uint8Array): void {
    pending.push(chunk);
    pendingLength += chunk.length;
  }

  // Removes and returns exactly n (<= pendingLength) bytes from the front of
  // the queue, splitting at most one array — no per-byte copies.
  function take(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let filled = 0;
    while (filled < n) {
      const head = pending[0];
      if (head === undefined) break; // unreachable: caller guarantees pendingLength >= n
      const need = n - filled;
      if (head.length <= need) {
        out.set(head, filled);
        filled += head.length;
        pending.shift();
      } else {
        out.set(head.subarray(0, need), filled);
        pending[0] = head.subarray(need);
        filled += need;
      }
    }
    pendingLength -= n;
    return out;
  }

  async function openNext(
    controller: TransformStreamDefaultController<Uint8Array>,
    sealed: Uint8Array,
  ): Promise<void> {
    if (chunkIndex >= MAX_CHUNKS) {
      throw new CounterOverflowError(`chunk index ${chunkIndex} exceeds ${MAX_CHUNKS}`);
    }
    const plaintext = await aead.open(nonceFor(baseNonce, chunkIndex), sealed);
    controller.enqueue(plaintext);
    chunkIndex++;
  }

  return {
    async transform(chunk, controller) {
      push(chunk);
      while (pendingLength >= ENC_CHUNK_SIZE) {
        await openNext(controller, take(ENC_CHUNK_SIZE));
      }
    },
    async flush(controller) {
      // A stream that ends exactly on a full-chunk boundary is truncation,
      // not success — the terminating short chunk (>=16 bytes) is mandatory.
      if (pendingLength < CHUNK_OVERHEAD) {
        throw new TruncationError(
          `truncated final chunk: ${pendingLength} bytes remaining, need at least ${CHUNK_OVERHEAD}`,
        );
      }
      await openNext(controller, take(pendingLength));
    },
  };
}
