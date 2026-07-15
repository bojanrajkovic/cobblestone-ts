import { describe, expect, it } from "vitest";
import { InvalidKeyError, InvalidSizeError } from "../errors.js";
import type { Aead } from "./aes-gcm.js";
import { checkAead, encryptedChunkCount, nonceFor, plaintextSize } from "./engine.js";

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
