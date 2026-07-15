import { concat } from "./bytes.js";
import { nodeCrypto, nodeCryptoFastPathActive } from "./aes-gcm.js";

const HASH_SIZE = 64; // SHA-512 output size
const MAX_LENGTH = 255 * HASH_SIZE;

// RFC 5869 §2.3 Expand only — `prk` is already a pseudorandom key, there is
// no Extract step. subtle.deriveBits('HKDF', ...), node:crypto's hkdf, and
// node:crypto's hkdfSync all always run Extract first, so none of them can
// be used here — only a manual per-block HMAC loop implements Expand alone.
export async function hkdfExpandSha512(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length > MAX_LENGTH) {
    throw new RangeError(`length must be at most ${MAX_LENGTH}, got ${length}`);
  }

  const blocks = Math.ceil(length / HASH_SIZE);
  const out = new Uint8Array(blocks * HASH_SIZE);

  if (nodeCryptoFastPathActive) {
    const { createHmac } = await nodeCrypto();
    const counter = new Uint8Array(1);
    let previous: Uint8Array = out.subarray(0, 0);

    for (let i = 1; i <= blocks; i++) {
      counter[0] = i;
      const block = createHmac("sha512", prk)
        .update(previous)
        .update(info)
        .update(counter)
        .digest();
      out.set(block, (i - 1) * HASH_SIZE);
      previous = out.subarray((i - 1) * HASH_SIZE, i * HASH_SIZE);
    }

    return out.subarray(0, length);
  }

  const key = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-512" }, false, [
    "sign",
  ]);

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
