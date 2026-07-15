import { describe, expect, it } from "vitest";
import {
  CounterOverflowError,
  InvalidKeyError,
  InvalidSizeError,
  TruncationError,
} from "../errors.js";
import type { Aead } from "./aes-gcm.js";
import { concat } from "./bytes.js";
import {
  checkAead,
  decryptTransformer,
  encryptedChunkCount,
  encryptTransformer,
  nonceFor,
  plaintextSize,
} from "./engine.js";

// Independent BigInt path: XOR the last 5 bytes of baseNonce with chunkIndex
// directly, rather than replicating nonceFor's Math.floor/>>> arithmetic.
function expectedNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
  const out = baseNonce.slice();
  const tailStart = out.length - 5;
  let tail = 0n;
  for (let i = 0; i < 5; i++) tail = (tail << 8n) | BigInt(out[tailStart + i] ?? 0);
  const xored = tail ^ BigInt(chunkIndex);
  for (let i = 0; i < 5; i++) {
    out[tailStart + i] = Number((xored >> BigInt(8 * (4 - i))) & 0xffn);
  }
  return out;
}

describe("nonceFor", () => {
  const baseNonce = crypto.getRandomValues(new Uint8Array(12));

  it.each([0, 1, 255, 256, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 38 - 1])(
    "XORs chunk index %d into the last 5 bytes only",
    (chunkIndex) => {
      const original = baseNonce.slice();
      const result = nonceFor(baseNonce, chunkIndex);

      expect(result).toEqual(expectedNonce(baseNonce, chunkIndex));
      expect(result.subarray(0, 7)).toEqual(baseNonce.subarray(0, 7)); // prefix untouched
      expect(baseNonce).toEqual(original); // input not mutated
    },
  );

  it("returns a copy, not the input array", () => {
    expect(nonceFor(baseNonce, 0)).not.toBe(baseNonce);
  });
});

describe("checkAead", () => {
  const fakeAead = (overrides: Partial<Aead> = {}): Aead => ({
    nonceSize: 12,
    overhead: 16,
    seal: (_n, p) => Promise.resolve(p),
    open: (_n, c) => Promise.resolve(c),
    ...overrides,
  });

  it("accepts a valid aead and matching base nonce", () => {
    expect(() => checkAead(fakeAead(), new Uint8Array(12))).not.toThrow();
  });

  it.each([15, 17])("rejects an aead with overhead %d", (overhead) => {
    expect(() => checkAead(fakeAead({ overhead: overhead as 16 }), new Uint8Array(12))).toThrow(
      InvalidKeyError,
    );
  });

  it.each([11, 33])("rejects an aead with nonceSize %d", (nonceSize) => {
    expect(() => checkAead(fakeAead({ nonceSize }), new Uint8Array(nonceSize))).toThrow(
      InvalidKeyError,
    );
  });

  it("rejects a baseNonce whose length doesn't match aead.nonceSize", () => {
    expect(() => checkAead(fakeAead({ nonceSize: 16 }), new Uint8Array(12))).toThrow(
      InvalidKeyError,
    );
  });
});

describe("encryptedChunkCount", () => {
  it.each([
    [16, 1],
    [16399, 1],
    [16416, 2],
    [16400 + 16, 2],
    [3 * 16400 + 16, 4],
  ])("%d encrypted bytes -> %d chunks", (size, expected) => {
    expect(encryptedChunkCount(size)).toBe(expected);
  });

  it.each([
    0,
    15,
    16400,
    32800,
    2 * 16400,
    (2 ** 38 + 1) * 16400 + 16,
    -1,
    0.5,
    2 ** 53,
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ])("rejects %d as an impossible encrypted size", (size) => {
    expect(() => encryptedChunkCount(size)).toThrow(InvalidSizeError);
  });
});

describe("plaintextSize", () => {
  it("subtracts total chunk overhead from the encrypted size", () => {
    expect(plaintextSize(16416)).toBe(16384);
    expect(plaintextSize(16)).toBe(0);
  });

  it.each([0, 16400])("propagates InvalidSizeError for impossible sizes (%d)", (size) => {
    expect(() => plaintextSize(size)).toThrow(InvalidSizeError);
  });
});

// A fake Aead that skips real crypto: seal appends 16 zero bytes and
// records the nonce it was called with, open strips the last 16 bytes
// unconditionally. Fast and deterministic for exercising the transformers'
// buffering/boundary logic in isolation from aes-gcm.ts (already covered by
// its own tests and by the vector suite).
function fakeChunkAead(): { aead: Aead; sealedNonces: Uint8Array[] } {
  const sealedNonces: Uint8Array[] = [];
  const aead: Aead = {
    nonceSize: 12,
    overhead: 16,
    seal: (nonce, plaintext) => {
      sealedNonces.push(nonce.slice());
      return Promise.resolve(concat(plaintext, new Uint8Array(16)));
    },
    open: (_nonce, ciphertext) => Promise.resolve(ciphertext.subarray(0, ciphertext.length - 16)),
  };
  return { aead, sealedNonces };
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

describe("encryptTransformer (fake aead)", () => {
  const baseNonce = new Uint8Array(12).fill(0x7);

  async function runEncrypt(size: number): Promise<{ chunks: Uint8Array[]; nonces: Uint8Array[] }> {
    const { aead, sealedNonces } = fakeChunkAead();
    const t = encryptTransformer(aead, baseNonce);
    const { controller, chunks } = fakeController();
    await t.transform(crypto.getRandomValues(new Uint8Array(size)), controller);
    await t.flush(controller);
    return { chunks, nonces: sealedNonces };
  }

  it.each([
    [0, [16]],
    [1, [17]],
    [16383, [16399]],
    [16384, [16400, 16]],
    [16385, [16400, 17]],
    [32768, [16400, 16400, 16]],
  ])("chunks a %d-byte input into sealed chunks of length %j", async (size, lengths) => {
    const { chunks, nonces } = await runEncrypt(size);
    expect(chunks.map((c) => c.length)).toEqual(lengths);
    expect(nonces).toHaveLength(lengths.length);
    nonces.forEach((n, i) => expect(n).toEqual(nonceFor(baseNonce, i)));
  });

  it("rejects sealing once chunkIndex reaches MAX_CHUNKS", async () => {
    const { aead } = fakeChunkAead();
    const t = encryptTransformer(aead, baseNonce, 2 ** 38); // ponytail: see engine.ts's startChunkIndex
    const { controller } = fakeController();
    await expect(t.flush(controller)).rejects.toThrow(CounterOverflowError);
  });
});

describe("decryptTransformer (fake aead)", () => {
  const baseNonce = new Uint8Array(12).fill(0x9);

  it("opens exactly at the 16400-byte boundary during transform, buffering nothing across it", async () => {
    const { aead } = fakeChunkAead();
    const t = decryptTransformer(aead, baseNonce);
    const { controller, chunks } = fakeController();

    await t.transform(new Uint8Array(16400), controller);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(16384);

    // Nothing left buffered — flush() on an empty queue is truncation, not
    // a (missing) second chunk.
    await expect(t.flush(controller)).rejects.toThrow(TruncationError);
  });

  it.each([0, 15])("flush() with %d pending bytes is truncation", async (pending) => {
    const { aead } = fakeChunkAead();
    const t = decryptTransformer(aead, baseNonce);
    const { controller } = fakeController();
    if (pending > 0) await t.transform(new Uint8Array(pending), controller);
    await expect(t.flush(controller)).rejects.toThrow(TruncationError);
  });

  it("flush() with exactly 16 pending bytes opens an empty final chunk", async () => {
    const { aead } = fakeChunkAead();
    const t = decryptTransformer(aead, baseNonce);
    const { controller, chunks } = fakeController();
    await t.transform(new Uint8Array(16), controller);
    await t.flush(controller);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(0);
  });

  it("rejects opening once chunkIndex reaches MAX_CHUNKS", async () => {
    const { aead } = fakeChunkAead();
    const t = decryptTransformer(aead, baseNonce, 2 ** 38); // ponytail: see engine.ts's startChunkIndex
    const { controller } = fakeController();
    await t.transform(new Uint8Array(16), controller); // buffered, not yet opened
    await expect(t.flush(controller)).rejects.toThrow(CounterOverflowError);
  });
});
