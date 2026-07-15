import { concat } from "./bytes.js";

const HASH_SIZE = 64; // SHA-512 output size
const MAX_LENGTH = 255 * HASH_SIZE;

// RFC 5869 §2.3 Expand only — `prk` is already a pseudorandom key, there is
// no Extract step. subtle.deriveBits('HKDF', ...) and node:crypto's hkdf
// always run Extract first, so neither can be used here.
export async function hkdfExpandSha512(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length > MAX_LENGTH) {
    throw new RangeError(`length must be at most ${MAX_LENGTH}, got ${length}`);
  }

  const key = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-512" }, false, [
    "sign",
  ]);

  const blocks = Math.ceil(length / HASH_SIZE);
  const out = new Uint8Array(blocks * HASH_SIZE);
  let previous = new Uint8Array(0);

  for (let i = 1; i <= blocks; i++) {
    const block = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, concat(previous, info, new Uint8Array([i]))),
    );
    out.set(block, (i - 1) * HASH_SIZE);
    previous = block;
  }

  return out.subarray(0, length);
}
