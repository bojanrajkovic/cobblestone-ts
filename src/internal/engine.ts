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
export const MAX_CHUNKS: number = 2 ** 38;

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
  // ponytail: chunkIndex is closure-local and otherwise unreachable from
  // outside — this test-only starting point lets CounterOverflowError be
  // exercised without actually driving 2**38 chunks through the
  // transformer. hazmat.ts never passes it.
  startChunkIndex = 0,
): Transformer<Uint8Array, Uint8Array> {
  const buf = new Uint8Array(CHUNK_SIZE);
  let filled = 0;
  let chunkIndex = startChunkIndex;

  async function sealChunk(
    controller: TransformStreamDefaultController<Uint8Array>,
    data: Uint8Array,
  ): Promise<void> {
    if (chunkIndex >= MAX_CHUNKS) {
      throw new CounterOverflowError(`chunk index ${chunkIndex} exceeds ${MAX_CHUNKS}`);
    }
    const sealed = await aead.seal(nonceFor(baseNonce, chunkIndex), data);
    controller.enqueue(sealed);
    chunkIndex++;
  }

  return {
    async transform(chunk, controller) {
      let offset = 0;
      while (offset < chunk.length) {
        // Fast path: nothing buffered, and a full chunk is already
        // contiguous in the caller's own write — seal it directly instead
        // of staging a copy through `buf` first. Both AEAD backends read
        // their plaintext argument synchronously (before any internal
        // await), so handing out a view into the caller's chunk is safe —
        // same mutation-hazard model as the copy this replaces.
        if (filled === 0 && chunk.length - offset >= CHUNK_SIZE) {
          await sealChunk(controller, chunk.subarray(offset, offset + CHUNK_SIZE));
          offset += CHUNK_SIZE;
          continue;
        }
        const take = Math.min(CHUNK_SIZE - filled, chunk.length - offset);
        buf.set(chunk.subarray(offset, offset + take), filled);
        filled += take;
        offset += take;
        if (filled === CHUNK_SIZE) {
          await sealChunk(controller, buf.subarray(0, CHUNK_SIZE));
          filled = 0;
        }
      }
    },
    async flush(controller) {
      // The final chunk is always emitted, even if it's empty — this is
      // what lets a decryptor distinguish a clean end from truncation.
      await sealChunk(controller, buf.subarray(0, filled));
    },
  };
}

export function decryptTransformer(
  aead: Aead,
  baseNonce: Uint8Array,
  // ponytail: see encryptTransformer's startChunkIndex — same test-only
  // escape hatch, same reason. hazmat.ts never passes it.
  startChunkIndex = 0,
): Transformer<Uint8Array, Uint8Array> {
  const pending: Uint8Array[] = [];
  let pendingLength = 0;
  let chunkIndex = startChunkIndex;

  function push(chunk: Uint8Array): void {
    pending.push(chunk);
    pendingLength += chunk.length;
  }

  // Removes and returns exactly n (<= pendingLength) bytes from the front of
  // the queue, splitting at most one array — no per-byte copies.
  function take(n: number): Uint8Array {
    // Fast path: the first queued array alone already covers the request —
    // return a view into it directly instead of allocating and copying into
    // a fresh buffer. Safe for the same reason as the encrypt-side fast
    // path: aead.open() reads its ciphertext argument synchronously.
    const first = pending[0];
    if (first !== undefined && first.length >= n) {
      if (first.length === n) {
        pending.shift();
      } else {
        pending[0] = first.subarray(n);
      }
      pendingLength -= n;
      return first.subarray(0, n);
    }

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

export interface ByteRangeSource {
  readonly size: number;
  readAt(offset: number, length: number): Promise<Uint8Array>;
}

export interface DecryptingReader {
  readonly plaintextSize: number;
  readAt(offset: number, length: number): Promise<Uint8Array>;
}

export type NormalizedSource = {
  size: number;
  readAt(offset: number, length: number): Promise<Uint8Array>;
};

export function normalizeSource(source: Blob | ByteRangeSource): NormalizedSource {
  if (typeof Blob !== "undefined" && source instanceof Blob) {
    return {
      size: source.size,
      async readAt(offset, length) {
        return new Uint8Array(await source.slice(offset, offset + length).arrayBuffer());
      },
    };
  }

  // Not a Blob per the guard above, so this can only be the other union
  // member — TS can't narrow through the `typeof Blob !== "undefined" &&`
  // guard on its own.
  const byteRangeSource = source as ByteRangeSource;
  if (!Number.isSafeInteger(byteRangeSource.size) || byteRangeSource.size < 0) {
    throw new InvalidSizeError(
      `source size must be a non-negative safe integer, got ${byteRangeSource.size}`,
    );
  }
  return byteRangeSource;
}

export function sectionSource(s: NormalizedSource, offset: number): NormalizedSource {
  return {
    size: s.size - offset,
    readAt: (o, l) => s.readAt(o + offset, l),
  };
}

export async function openRawReader(
  aead: Aead,
  baseNonce: Uint8Array,
  source: NormalizedSource,
): Promise<DecryptingReader> {
  const chunks = encryptedChunkCount(source.size);
  const ptSize = source.size - chunks * CHUNK_OVERHEAD;

  let cache: { chunkIndex: number; plaintext: Uint8Array } | undefined;

  async function openChunk(chunkIndex: number): Promise<Uint8Array> {
    if (cache?.chunkIndex === chunkIndex) return cache.plaintext;

    const chunkOffset = chunkIndex * ENC_CHUNK_SIZE;
    const sealedLength = Math.min(ENC_CHUNK_SIZE, source.size - chunkOffset);
    const sealed = await source.readAt(chunkOffset, sealedLength);
    if (sealed.length !== sealedLength) {
      throw new TruncationError(
        `short read for chunk ${chunkIndex}: expected ${sealedLength} bytes, got ${sealed.length}`,
      );
    }

    const plaintext = await aead.open(nonceFor(baseNonce, chunkIndex), sealed);
    cache = { chunkIndex, plaintext }; // advisory, single-entry — never decrypt into a cached buffer
    return plaintext;
  }

  // Eagerly authenticate the final chunk now: this pins the message length
  // at open() time instead of trusting an unverified source.size.
  await openChunk(chunks - 1);

  return {
    plaintextSize: ptSize,

    async readAt(offset, length) {
      if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new InvalidSizeError(`offset must be a non-negative safe integer, got ${offset}`);
      }
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new InvalidSizeError(`length must be a non-negative safe integer, got ${length}`);
      }
      if (offset > ptSize) {
        throw new InvalidSizeError(`offset ${offset} exceeds plaintext size ${ptSize}`);
      }
      if (length === 0) return new Uint8Array(0);

      const n = Math.min(length, ptSize - offset);
      const result = new Uint8Array(n);
      let pos = offset;
      let filled = 0;
      while (filled < n) {
        const chunkIndex = Math.floor(pos / CHUNK_SIZE);
        const plaintext = await openChunk(chunkIndex);
        const withinChunk = pos - chunkIndex * CHUNK_SIZE;
        const take = Math.min(plaintext.length - withinChunk, n - filled);
        result.set(plaintext.subarray(withinChunk, withinChunk + take), filled);
        filled += take;
        pos += take;
      }
      return result;
    },
  };
}
