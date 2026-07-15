import { describe, expect, it } from "vitest";
import * as cobblestone128 from "./src/cobblestone-128.js";
import * as cobblestone256 from "./src/cobblestone-256.js";
import type { CobblestoneOptions } from "./src/cobblestone-128.js";
import { concat } from "./src/internal/bytes.js";
import {
  type Aead,
  aesGcm,
  AuthenticationError,
  type ByteRangeSource,
  CobblestoneError,
  CommitmentMismatchError,
  encryptedChunkCount,
  InvalidKeyError,
  InvalidSizeError,
  openRawDecryptingReader,
  plaintextSize,
  RawDecryptionStream,
  RawEncryptionStream,
  TruncationError,
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

function byteRangeSource(data: Uint8Array): ByteRangeSource {
  return {
    size: data.length,
    readAt: (offset, length) => Promise.resolve(data.subarray(offset, offset + length)),
  };
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

    it("opens a random-access reader over rawPayload for every aeadKey vector", async () => {
      const vectors = await loadVectors(url);
      let checked = 0;

      for (const v of vectors) {
        if (v.aeadKey === undefined || v.baseNonce === undefined) continue; // tc21-30 lack derived params by design
        checked++;

        const rawPayload = v.ct.subarray(56);
        const aead = await aesGcm(v.aeadKey);
        const label = `tc${v.tcId}: ${v.comment}`;

        // tc1 additionally proves the Blob-detection path in normalizeSource.
        const sources: (Blob | ByteRangeSource)[] = [byteRangeSource(rawPayload)];
        if (v.tcId === 1) sources.push(new Blob([rawPayload]));

        for (const source of sources) {
          let reader: Awaited<ReturnType<typeof openRawDecryptingReader>> | undefined;
          let openError: unknown;
          try {
            reader = await openRawDecryptingReader(aead, v.baseNonce, source);
          } catch (e) {
            openError = e;
          }

          if (v.result === "valid") {
            expect(openError, label).toBeUndefined();
            const full = await reader?.readAt(0, reader.plaintextSize);
            expect(full?.length, label).toBe(v.msgLength);
            expect(await sha512(full ?? new Uint8Array(0)), label).toEqual(v.msgSha512);
            expect((await reader?.readAt(reader.plaintextSize, 1))?.length, label).toBe(0);
          } else if (openError !== undefined) {
            expect(openError, label).toBeInstanceOf(CobblestoneError);
          } else {
            // Final chunk happened to authenticate (e.g. a chunk-reorder
            // vector) — the corruption must still surface somewhere in a
            // full read.
            await expect(reader?.readAt(0, reader.plaintextSize), label).rejects.toBeInstanceOf(
              CobblestoneError,
            );
          }
        }
      }

      expect(checked).toBe(25);
    });
  });
}

// --- high-level API (header, key derivation, commitment) against the same vectors ---

type StreamCtor = new (
  key: Uint8Array,
  opts?: CobblestoneOptions,
) => TransformStream<Uint8Array, Uint8Array>;

// Error-class matrix from the vector file's own flags (normative — see
// testdata/*.json comments/flags per tcId). If any vector maps to the wrong
// class here, our code is wrong: the fix belongs in src/cobblestone.ts, not
// in this table.
const TRUNCATION_TC = new Set([16, 17, 19, 20, 27, 28, 29, 30, 31]);
const COMMITMENT_MISMATCH_TC = new Set([21, 22, 25, 26]);
const INVALID_KEY_TC = new Set([23, 24]);
const AUTHENTICATION_TC = new Set([11, 12, 13, 14, 15, 18, 32, 33, 34, 35]);

function expectedStreamErrorClass(tcId: number) {
  if (TRUNCATION_TC.has(tcId)) return TruncationError;
  if (COMMITMENT_MISMATCH_TC.has(tcId)) return CommitmentMismatchError;
  if (INVALID_KEY_TC.has(tcId)) return InvalidKeyError;
  if (AUTHENTICATION_TC.has(tcId)) return AuthenticationError;
  return undefined; // valid vectors (tc1-10)
}

// The reader validates structural size up front instead of discovering
// truncation mid-stream, so every TruncationError above becomes
// InvalidSizeError here; every other class is unchanged.
function expectedReaderErrorClass(tcId: number) {
  const streamClass = expectedStreamErrorClass(tcId);
  return streamClass === TruncationError ? InvalidSizeError : streamClass;
}

// Drives a freshly-constructed EncryptionStream/DecryptionStream to
// completion, writing `input` as one chunk or (if given an array) as
// several. A synchronous constructor throw (bad key size) is captured the
// same way as a mid-stream rejection, so callers get one uniform shape.
async function driveStream(
  StreamClass: StreamCtor,
  key: Uint8Array,
  input: Uint8Array | Uint8Array[],
  opts?: CobblestoneOptions,
): Promise<{ delivered: Uint8Array; error: unknown }> {
  let stream: TransformStream<Uint8Array, Uint8Array>;
  try {
    stream = new StreamClass(key, opts);
  } catch (e) {
    return { delivered: new Uint8Array(0), error: e };
  }

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

  for (const piece of Array.isArray(input) ? input : [input]) {
    await writer.write(piece).catch(() => {});
  }
  await writer.close().catch(() => {});
  await readLoop;

  return { delivered: concat(...chunks), error };
}

// Splits into 2-3 non-empty pieces to exercise multi-write streaming; tiny
// (<2-byte) plaintexts just get a single write since finer splitting isn't
// meaningful.
function writerSlices(data: Uint8Array): Uint8Array[] {
  if (data.length < 2) return [data];
  const third = Math.max(1, Math.floor(data.length / 3));
  const cuts = [...new Set([0, third, third * 2, data.length])].sort((a, b) => a - b);
  const out: Uint8Array[] = [];
  for (let i = 0; i < cuts.length - 1; i++) {
    out.push(data.subarray(cuts[i] ?? 0, cuts[i + 1] ?? data.length));
  }
  return out;
}

const HIGH_LEVEL_SUITES = [
  { url: new URL("./testdata/vectors_aes_128_gcm.json", import.meta.url), mod: cobblestone128 },
  { url: new URL("./testdata/vectors_aes_256_gcm.json", import.meta.url), mod: cobblestone256 },
];

for (const { url, mod } of HIGH_LEVEL_SUITES) {
  describe(`high-level API against ${url.pathname.split("/").pop()}`, () => {
    it("one-shot decrypt matches every vector", async () => {
      const vectors = await loadVectors(url);
      expect(vectors).toHaveLength(35);

      for (const v of vectors) {
        const opts: CobblestoneOptions = { context: v.ctxBytes };
        const label = `tc${v.tcId}: ${v.comment}`;

        if (v.result === "valid") {
          const pt = await mod.decrypt(v.key, v.ct, opts);
          expect(pt.length, label).toBe(v.msgLength);
          expect(await sha512(pt), label).toEqual(v.msgSha512);
        } else {
          await expect(mod.decrypt(v.key, v.ct, opts), label).rejects.toBeInstanceOf(
            expectedStreamErrorClass(v.tcId),
          );
        }
      }
    });

    it("DecryptionStream matches every vector, delivering partial-plaintext prefixes on failure", async () => {
      const vectors = await loadVectors(url);

      for (const v of vectors) {
        const opts: CobblestoneOptions = { context: v.ctxBytes };
        const label = `tc${v.tcId}: ${v.comment}`;
        const { delivered, error } = await driveStream(mod.DecryptionStream, v.key, v.ct, opts);

        if (v.result === "valid") {
          expect(error, label).toBeUndefined();
          expect(delivered.length, label).toBe(v.msgLength);
          expect(await sha512(delivered), label).toEqual(v.msgSha512);
        } else {
          expect(error, label).toBeInstanceOf(expectedStreamErrorClass(v.tcId));
          if (v.msgLength !== undefined) {
            expect(delivered.length, label).toBeGreaterThanOrEqual(v.msgLength);
            expect(await sha512(delivered.subarray(0, v.msgLength)), label).toEqual(v.msgSha512);
          }
        }
      }
    });

    it("openDecryptingReader matches every vector", async () => {
      const vectors = await loadVectors(url);

      for (const v of vectors) {
        const opts: CobblestoneOptions = { context: v.ctxBytes };
        const label = `tc${v.tcId}: ${v.comment}`;
        const source = byteRangeSource(v.ct);

        let reader: Awaited<ReturnType<typeof mod.openDecryptingReader>> | undefined;
        let openError: unknown;
        try {
          reader = await mod.openDecryptingReader(v.key, source, opts);
        } catch (e) {
          openError = e;
        }

        if (v.result === "valid") {
          expect(openError, label).toBeUndefined();
          const full = await reader?.readAt(0, reader.plaintextSize);
          expect(full?.length, label).toBe(v.msgLength);
          expect(await sha512(full ?? new Uint8Array(0)), label).toEqual(v.msgSha512);
          expect((await reader?.readAt(reader.plaintextSize, 1))?.length, label).toBe(0);
        } else if (openError !== undefined) {
          expect(openError, label).toBeInstanceOf(expectedReaderErrorClass(v.tcId));
        } else {
          // Final chunk happened to authenticate (tc13, tc15, tc33, tc34) —
          // the corruption must still surface on a full read.
          await expect(reader?.readAt(0, reader.plaintextSize), label).rejects.toBeInstanceOf(
            AuthenticationError,
          );
        }
      }
    });

    it("round-trips every valid vector through one-shot and writer-style encryption", async () => {
      const vectors = await loadVectors(url);

      for (const v of vectors) {
        if (v.result !== "valid") continue;
        const opts: CobblestoneOptions = { context: v.ctxBytes };
        const label = `tc${v.tcId}: ${v.comment}`;
        const pt = await mod.decrypt(v.key, v.ct, opts);

        const reEncrypted = await mod.encrypt(v.key, pt, opts);
        expect(await mod.decrypt(v.key, reEncrypted, opts), label).toEqual(pt);

        const { delivered, error } = await driveStream(
          mod.EncryptionStream,
          v.key,
          writerSlices(pt),
          opts,
        );
        expect(error, label).toBeUndefined();
        expect(await mod.decrypt(v.key, delivered, opts), label).toEqual(pt);
      }
    });

    it("plaintextSize and ciphertextSize match every valid vector", async () => {
      const vectors = await loadVectors(url);

      for (const v of vectors) {
        if (v.result !== "valid") continue;
        const label = `tc${v.tcId}: ${v.comment}`;
        if (v.msgLength === undefined) throw new Error(`${label}: valid vector missing msgLength`);

        expect(mod.plaintextSize(v.ct.length), label).toBe(v.msgLength);
        expect(mod.ciphertextSize(v.msgLength), label).toBe(v.ct.length);
      }
    });

    it("tc23/tc24 (bad key size) throw synchronously from constructors and reject from every async entry point", async () => {
      const vectors = await loadVectors(url);

      for (const v of vectors) {
        if (v.tcId !== 23 && v.tcId !== 24) continue;
        const label = `tc${v.tcId}: ${v.comment}`;

        expect(() => new mod.EncryptionStream(v.key), label).toThrow(InvalidKeyError);
        expect(() => new mod.DecryptionStream(v.key), label).toThrow(InvalidKeyError);
        await expect(mod.encrypt(v.key, new Uint8Array(0)), label).rejects.toBeInstanceOf(
          InvalidKeyError,
        );
        await expect(mod.decrypt(v.key, v.ct), label).rejects.toBeInstanceOf(InvalidKeyError);
        await expect(
          mod.openDecryptingReader(v.key, byteRangeSource(v.ct)),
          label,
        ).rejects.toBeInstanceOf(InvalidKeyError);
      }
    });
  });
}
