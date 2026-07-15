import { describe, expect, it } from "vitest";
import { hkdfExpandSha512 } from "./hkdf.js";

const PRK = new Uint8Array(64).fill(0x0b);
const INFO = new TextEncoder().encode("cobblestone-ts hkdf test");
const HASH_SIZE = 64;

// Independent re-implementation of RFC 5869 §2.3 Expand, so the assertions
// below aren't just checking the implementation against itself.
async function referenceExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-512" }, false, [
    "sign",
  ]);
  const blocks = Math.ceil(length / HASH_SIZE);
  const out = new Uint8Array(blocks * HASH_SIZE);
  let previous = new Uint8Array(0);
  for (let i = 1; i <= blocks; i++) {
    const input = new Uint8Array(previous.length + info.length + 1);
    input.set(previous, 0);
    input.set(info, previous.length);
    input[input.length - 1] = i;
    const block = new Uint8Array(await crypto.subtle.sign("HMAC", key, input));
    out.set(block, (i - 1) * HASH_SIZE);
    previous = block;
  }
  return out.subarray(0, length);
}

describe("hkdfExpandSha512", () => {
  it.each([60, 76])("matches an independently computed reference for length %d", async (length) => {
    expect(await hkdfExpandSha512(PRK, INFO, length)).toEqual(
      await referenceExpand(PRK, INFO, length),
    );
  });

  it.each([63, 64, 65, 128])(
    "matches the reference across block boundary length %d",
    async (length) => {
      expect(await hkdfExpandSha512(PRK, INFO, length)).toEqual(
        await referenceExpand(PRK, INFO, length),
      );
    },
  );

  it("rejects a length beyond 255 blocks", async () => {
    await expect(hkdfExpandSha512(PRK, INFO, 255 * HASH_SIZE + 1)).rejects.toThrow(RangeError);
  });
});
