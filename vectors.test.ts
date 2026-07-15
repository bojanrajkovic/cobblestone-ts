import { describe, expect, it } from "vitest";
import { concat } from "./src/internal/bytes.js";
import {
  type Aead,
  aesGcm,
  CobblestoneError,
  encryptedChunkCount,
  InvalidSizeError,
  plaintextSize,
  RawDecryptionStream,
  RawEncryptionStream,
} from "./src/hazmat.js";
import { loadVectors } from "./vectors-harness.js";

const VECTOR_FILES = [
  new URL("./testdata/vectors_aes_128_gcm.json", import.meta.url),
  new URL("./testdata/vectors_aes_256_gcm.json", import.meta.url),
];

async function sha512(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", data));
}

// Splits `data` into a few slices landing at different offsets relative to
// the 16400-byte sealed chunk boundary — not one slice per chunk, so this
// stays cheap on the multi-megabyte vectors (hundreds of chunks).
function slices(data: Uint8Array): Uint8Array[] {
  if (data.length === 0) return [];
  const boundaries = [1, 4001, 12399, 16403, 32817];
  const cuts = [...new Set([0, ...boundaries.filter((b) => b < data.length), data.length])].sort(
    (a, b) => a - b,
  );
  const out: Uint8Array[] = [];
  for (let i = 0; i < cuts.length - 1; i++) {
    out.push(data.subarray(cuts[i] ?? 0, cuts[i + 1] ?? data.length));
  }
  return out;
}

async function driveDecryption(
  aead: Aead,
  baseNonce: Uint8Array,
  sealed: Uint8Array,
): Promise<{ delivered: Uint8Array; error: unknown }> {
  const stream = new RawDecryptionStream(aead, baseNonce);
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

  for (const slice of slices(sealed)) {
    await writer.write(slice).catch(() => {});
  }
  await writer.close().catch(() => {});
  await readLoop;

  return { delivered: concat(...chunks), error };
}

async function driveEncryption(
  aead: Aead,
  baseNonce: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const stream = new RawEncryptionStream(aead, baseNonce);
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();
  const chunks: Uint8Array[] = [];

  const readLoop = (async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      chunks.push(value);
    }
  })();

  for (const slice of slices(plaintext)) {
    await writer.write(slice);
  }
  await writer.close();
  await readLoop;

  return concat(...chunks);
}

// A length is shaped like a valid raw chunked ciphertext iff, after peeling
// off as many full 16400-byte sealed chunks as possible, what's left could
// be the final chunk: 16..16399 sealed bytes. This is independent of
// encryptedChunkCount's ceil/floor formula — that function is under test.
function isArithmeticallyValidLength(length: number): boolean {
  let remaining = length;
  while (remaining > 16399) remaining -= 16400;
  return remaining >= 16 && remaining <= 16399;
}

for (const url of VECTOR_FILES) {
  describe(`raw chunked streams against ${url.pathname.split("/").pop()}`, () => {
    it("decrypts, size-checks, and byte-exact re-encrypts every aeadKey vector", async () => {
      const vectors = await loadVectors(url);
      let checked = 0;

      for (const v of vectors) {
        if (v.aeadKey === undefined || v.baseNonce === undefined) continue; // tc21-30 lack derived params by design
        checked++;

        const rawPayload = v.ct.subarray(56);
        const aead = await aesGcm(v.aeadKey);
        const label = `tc${v.tcId}: ${v.comment}`;

        if (isArithmeticallyValidLength(rawPayload.length)) {
          expect(encryptedChunkCount(rawPayload.length), label).toBeGreaterThan(0);
        } else {
          expect(() => encryptedChunkCount(rawPayload.length), label).toThrow(InvalidSizeError);
        }

        const { delivered, error } = await driveDecryption(aead, v.baseNonce, rawPayload);

        if (v.result === "valid") {
          expect(error, label).toBeUndefined();
          expect(delivered.length, label).toBe(v.msgLength);
          expect(await sha512(delivered), label).toEqual(v.msgSha512);
          expect(plaintextSize(rawPayload.length), label).toBe(v.msgLength);

          const reEncrypted = await driveEncryption(aead, v.baseNonce, delivered);
          expect(reEncrypted, `${label}: byte-exact re-encryption`).toEqual(rawPayload);
        } else {
          expect(error, label).toBeInstanceOf(CobblestoneError);
          if (v.msgLength !== undefined) {
            expect(delivered.length, label).toBeGreaterThanOrEqual(v.msgLength);
            expect(await sha512(delivered.subarray(0, v.msgLength)), label).toEqual(v.msgSha512);
          }
          if (v.tcId === 31) {
            expect(delivered.length, "tc31 sentinel: full chunk delivered before truncation").toBe(
              16384,
            );
          }
        }
      }

      expect(checked).toBe(25);
    });
  });
}
