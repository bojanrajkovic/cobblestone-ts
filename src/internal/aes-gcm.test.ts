import { createCipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AuthenticationError, InvalidKeyError } from "../errors.js";
import { aesGcm, nodeCryptoFastPathActive } from "./aes-gcm.js";

// Guards the forced-webcrypto vitest project: if the env var ever stops
// reaching module evaluation, that project silently degrades into a
// duplicate fast-path run — this is the test that catches it.
it.runIf(process.env["COBBLESTONE_FORCE_WEBCRYPTO"] === "1")(
  "COBBLESTONE_FORCE_WEBCRYPTO=1 disables the fast path",
  () => {
    expect(nodeCryptoFastPathActive).toBe(false);
  },
);

describe("aesGcm round-trip", () => {
  const key = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  it.each([0, 1, 16384])("round-trips a %d-byte payload", async (size) => {
    const aead = await aesGcm(key);
    const plaintext = crypto.getRandomValues(new Uint8Array(size));

    const sealed = await aead.seal(nonce, plaintext);
    expect(sealed.byteLength).toBe(plaintext.byteLength + aead.overhead);

    const opened = await aead.open(nonce, sealed);
    expect(opened).toEqual(plaintext);
  });

  it("rejects a tampered ciphertext byte", async () => {
    const aead = await aesGcm(key);
    const sealed = await aead.seal(nonce, new Uint8Array([1, 2, 3]));
    const tampered = sealed.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    await expect(aead.open(nonce, tampered)).rejects.toThrow(AuthenticationError);
  });

  it("rejects a tampered tag byte", async () => {
    const aead = await aesGcm(key);
    const sealed = await aead.seal(nonce, new Uint8Array([1, 2, 3]));
    const tampered = sealed.slice();
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 0xff;
    await expect(aead.open(nonce, tampered)).rejects.toThrow(AuthenticationError);
  });

  it("rejects when opened with a different nonce", async () => {
    const aead = await aesGcm(key);
    const sealed = await aead.seal(nonce, new Uint8Array([1, 2, 3]));
    const otherNonce = crypto.getRandomValues(new Uint8Array(12));
    await expect(aead.open(otherNonce, sealed)).rejects.toThrow(AuthenticationError);
  });

  it.each([15, 17, 24, 33])("rejects a %d-byte key", async (size) => {
    await expect(aesGcm(new Uint8Array(size))).rejects.toThrow(InvalidKeyError);
  });

  it("is immune to the caller mutating the key after aesGcm() resolves", async () => {
    const mutableKey = crypto.getRandomValues(new Uint8Array(16));
    const originalKey = mutableKey.slice();
    const aead = await aesGcm(mutableKey);

    mutableKey.fill(0); // simulate zeroing key material once the Aead is derived

    const plaintext = new Uint8Array([1, 2, 3]);
    const sealed = await aead.seal(nonce, plaintext);

    const referenceAead = await aesGcm(originalKey);
    expect(sealed).toEqual(await referenceAead.seal(nonce, plaintext));
  });
});

describe("aesGcm cross-implementation check against node:crypto", () => {
  it("matches node:crypto for AES-128-GCM", async () => {
    const key = new Uint8Array(16).fill(0x42);
    const nonce = new Uint8Array(12).fill(0x24);
    const plaintext = new TextEncoder().encode("cobblestone-ts cross-check");

    const cipher = createCipheriv("aes-128-gcm", key, nonce);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const expected = new Uint8Array(Buffer.concat([ct, cipher.getAuthTag()]));

    const aead = await aesGcm(key);
    expect(await aead.seal(nonce, plaintext)).toEqual(expected);
  });

  it("matches node:crypto for AES-256-GCM", async () => {
    const key = new Uint8Array(32).fill(0x99);
    const nonce = new Uint8Array(12).fill(0x11);
    const plaintext = new TextEncoder().encode("cobblestone-ts cross-check 256");

    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const expected = new Uint8Array(Buffer.concat([ct, cipher.getAuthTag()]));

    const aead = await aesGcm(key);
    expect(await aead.seal(nonce, plaintext)).toEqual(expected);
  });
});
