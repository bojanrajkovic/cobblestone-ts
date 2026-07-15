import { describe, expect, it } from "vitest";
import { InvalidKeyError, InvalidSizeError } from "../errors.js";
import { loadVectors } from "../../vectors-harness.js";
import { AES_128_GCM, AES_256_GCM, type AeadDescriptor, deriveMessageParams } from "./derive.js";

const VECTOR_FILES: { url: URL; descriptor: AeadDescriptor }[] = [
  {
    url: new URL("../../testdata/vectors_aes_128_gcm.json", import.meta.url),
    descriptor: AES_128_GCM,
  },
  {
    url: new URL("../../testdata/vectors_aes_256_gcm.json", import.meta.url),
    descriptor: AES_256_GCM,
  },
];

for (const { url, descriptor } of VECTOR_FILES) {
  describe(`deriveMessageParams against ${descriptor.ianaName} vectors`, () => {
    it("derives aeadKey, baseNonce, and commitment matching the vectors", async () => {
      const vectors = await loadVectors(url);
      let checked = 0;

      for (const v of vectors) {
        if (v.aeadKey === undefined || v.baseNonce === undefined) continue; // tc21-30 lack derived params by design

        const salt = v.ct.subarray(0, 24);
        const expectedCommitment = v.ct.subarray(24, 56);
        const params = await deriveMessageParams(descriptor, v.key, salt, v.ctxBytes);

        expect(params.aeadKey, `tc${v.tcId}: ${v.comment}`).toEqual(v.aeadKey);
        expect(params.baseNonce, `tc${v.tcId}: ${v.comment}`).toEqual(v.baseNonce);
        expect(params.commitment, `tc${v.tcId}: ${v.comment}`).toEqual(expectedCommitment);
        checked++;
      }

      expect(checked).toBe(25);
    });
  });
}

describe("deriveMessageParams validation", () => {
  it.each([15, 17, 32])("rejects a %d-byte key for AES_128_GCM", async (size) => {
    await expect(
      deriveMessageParams(AES_128_GCM, new Uint8Array(size), new Uint8Array(24), ""),
    ).rejects.toThrow(InvalidKeyError);
  });

  it("rejects a 16-byte key for AES_256_GCM", async () => {
    await expect(
      deriveMessageParams(AES_256_GCM, new Uint8Array(16), new Uint8Array(24), ""),
    ).rejects.toThrow(InvalidKeyError);
  });

  it.each([23, 25])("rejects a %d-byte salt", async (size) => {
    await expect(
      deriveMessageParams(AES_128_GCM, new Uint8Array(16), new Uint8Array(size), ""),
    ).rejects.toThrow(InvalidSizeError);
  });
});
