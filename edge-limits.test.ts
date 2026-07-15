// Continuation of edge.test.ts, split out once that file passed ~600 lines.
// Ports the intent of the Go reference harness's TestMaxChunks/checkCounter
// and the TransformStream-specific header-edge cases.

import { describe, expect, it } from "vitest";
import * as cobblestone128 from "./src/cobblestone-128.js";
import { CounterOverflowError, InvalidSizeError, TruncationError } from "./src/errors.js";
import { concat } from "./src/internal/bytes.js";
import type { Aead } from "./src/internal/aes-gcm.js";
import {
  CHUNK_OVERHEAD,
  CHUNK_SIZE,
  decryptTransformer,
  encryptedChunkCount,
  encryptTransformer,
  MAX_CHUNKS,
  nonceFor,
} from "./src/internal/engine.js";

// A fake Aead that skips real crypto: seal appends 16 zero bytes and
// records the nonce it was called with, open strips the last 16
// unconditionally and records that nonce too. Fast and deterministic for
// exercising MAX_CHUNKS boundary arithmetic without driving 2**38 real
// chunks through AES-GCM.
function fakeChunkAead(): {
  aead: Aead;
  sealedNonces: Uint8Array[];
  openedNonces: Uint8Array[];
} {
  const sealedNonces: Uint8Array[] = [];
  const openedNonces: Uint8Array[] = [];
  const aead: Aead = {
    nonceSize: 12,
    overhead: 16,
    seal: (nonce, plaintext) => {
      sealedNonces.push(nonce.slice());
      return Promise.resolve(concat(plaintext, new Uint8Array(16)));
    },
    open: (nonce, ciphertext) => {
      openedNonces.push(nonce.slice());
      return Promise.resolve(ciphertext.subarray(0, ciphertext.length - 16));
    },
  };
  return { aead, sealedNonces, openedNonces };
}

function fakeController(): {
  controller: TransformStreamDefaultController<Uint8Array>;
  chunks: Uint8Array[];
} {
  const chunks: Uint8Array[] = [];
  const controller = {
    enqueue: (chunk: Uint8Array) => chunks.push(chunk),
  } as unknown as TransformStreamDefaultController<Uint8Array>;
  return { controller, chunks };
}

async function drive(
  stream: TransformStream<Uint8Array, Uint8Array>,
  pieces: Uint8Array[],
): Promise<{ delivered: Uint8Array; error: unknown }> {
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();
  const chunks: Uint8Array[] = [];
  let error: unknown;

  const readLoop = (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        chunks.push(value);
      }
    } catch (e) {
      error = e;
    }
  })();

  for (const piece of pieces) {
    await writer.write(piece).catch(() => {});
  }
  await writer.close().catch(() => {});
  await readLoop;

  return { delivered: concat(...chunks), error };
}

function prefixByteWrites(data: Uint8Array, n: number): Uint8Array[] {
  const pieces = Array.from({ length: n }, (_, i) => data.subarray(i, i + 1));
  pieces.push(data.subarray(n));
  return pieces;
}

function fillPattern(size: number): Uint8Array {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = i & 0xff;
  return out;
}

describe("counter limits with a fake AEAD (Go: TestMaxChunks/checkCounter)", () => {
  const baseNonce = new Uint8Array(12).fill(0x3);

  it("seals the boundary chunk at 2**38-1, then overflows sealing flush's mandatory final chunk", async () => {
    const { aead, sealedNonces } = fakeChunkAead();
    const t = encryptTransformer(aead, baseNonce, MAX_CHUNKS - 1);
    const { controller } = fakeController();

    await t.transform(new Uint8Array(CHUNK_SIZE), controller); // fills+seals index MAX_CHUNKS-1
    expect(sealedNonces).toEqual([nonceFor(baseNonce, MAX_CHUNKS - 1)]);

    await expect(t.flush(controller)).rejects.toThrow(CounterOverflowError);
  });

  it("seals a legal short final chunk at index 2**38-1 without overflowing", async () => {
    const { aead } = fakeChunkAead();
    const t = encryptTransformer(aead, baseNonce, MAX_CHUNKS - 1);
    const { controller, chunks } = fakeController();

    await t.transform(new Uint8Array(CHUNK_SIZE - 1), controller); // buffered, not sealed yet
    await t.flush(controller); // seals the short final chunk at MAX_CHUNKS-1 -- legal

    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(CHUNK_SIZE - 1 + CHUNK_OVERHEAD);
  });

  it("opens the full chunk at index 2**38-1, then overflows opening the short final chunk", async () => {
    const { aead, openedNonces } = fakeChunkAead();
    const t = decryptTransformer(aead, baseNonce, MAX_CHUNKS - 1);
    const { controller } = fakeController();

    await t.transform(new Uint8Array(CHUNK_SIZE + CHUNK_OVERHEAD), controller); // opens index MAX_CHUNKS-1
    expect(openedNonces).toEqual([nonceFor(baseNonce, MAX_CHUNKS - 1)]);

    await t.transform(new Uint8Array(20), controller); // buffered short chunk, not yet opened
    await expect(t.flush(controller)).rejects.toThrow(CounterOverflowError);
  });

  it("records nonceFor(baseNonce, 0..2) on a fresh zero-start encrypt run", async () => {
    const { aead, sealedNonces } = fakeChunkAead();
    const t = encryptTransformer(aead, baseNonce);
    const { controller } = fakeController();

    await t.transform(new Uint8Array(CHUNK_SIZE * 3), controller);
    expect(sealedNonces).toEqual([0, 1, 2].map((i) => nonceFor(baseNonce, i)));
  });

  it("records nonceFor(baseNonce, 0..2) on a fresh zero-start decrypt run", async () => {
    const { aead, openedNonces } = fakeChunkAead();
    const t = decryptTransformer(aead, baseNonce);
    const { controller } = fakeController();

    await t.transform(new Uint8Array((CHUNK_SIZE + CHUNK_OVERHEAD) * 3), controller);
    expect(openedNonces).toEqual([0, 1, 2].map((i) => nonceFor(baseNonce, i)));
  });

  it("rejects InvalidSizeError for an encrypted size past the chunk cap (pure arithmetic)", () => {
    expect(() => encryptedChunkCount((2 ** 38 + 1) * 16400 + 16)).toThrow(InvalidSizeError);
  });
});

describe("DecryptionStream header edges", () => {
  it("rejects TruncationError when closed after exactly 55 bytes", async () => {
    const key = crypto.getRandomValues(new Uint8Array(cobblestone128.KEY_SIZE));
    const { error } = await drive(new cobblestone128.DecryptionStream(key), [new Uint8Array(55)]);
    expect(error).toBeInstanceOf(TruncationError);
  });

  it("rejects TruncationError for a valid 56-byte header with zero chunks (not an empty message)", async () => {
    const key = crypto.getRandomValues(new Uint8Array(cobblestone128.KEY_SIZE));
    const ciphertext = await cobblestone128.encrypt(key, fillPattern(1000));
    const header = ciphertext.subarray(0, 56);

    const { error } = await drive(new cobblestone128.DecryptionStream(key), [header]);
    expect(error).toBeInstanceOf(TruncationError);
  });

  it("decrypts correctly when the header arrives as 56 one-byte writes", async () => {
    const key = crypto.getRandomValues(new Uint8Array(cobblestone128.KEY_SIZE));
    const plaintext = fillPattern(20000);
    const ciphertext = await cobblestone128.encrypt(key, plaintext);

    const { delivered, error } = await drive(
      new cobblestone128.DecryptionStream(key),
      prefixByteWrites(ciphertext, 56),
    );
    expect(error).toBeUndefined();
    expect(delivered).toEqual(plaintext);
  });
});
