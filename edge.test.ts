// Edge-case hardening suite, porting the intent of the Go reference
// implementation's edge tests. Each describe block names the Go ancestor
// it's standing in for.

import { describe, expect, it } from "vitest";
import * as cobblestone128 from "./src/cobblestone-128.js";
import { CHUNK_SIZE } from "./src/internal/engine.js";
import { concat } from "./src/internal/bytes.js";

// Deterministic counter pattern — content doesn't matter for these tests,
// only length, and this is cheaper than crypto.getRandomValues at the
// larger sizes exercised below.
function fillPattern(size: number): Uint8Array {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = i & 0xff;
  return out;
}

function flipByte(data: Uint8Array, index: number): Uint8Array {
  const out = data.slice();
  out[index] = (out[index] ?? 0) ^ 0xff;
  return out;
}

// --- write-pattern helpers, each returning the pieces to feed a writer ---

function oneWrite(data: Uint8Array): Uint8Array[] {
  return [data];
}

// cap bounds the number of individual 1-byte writes; anything left over
// after `cap` bytes goes out as one final piece, keeping runtime sane for
// large inputs while still exercising true 1-byte delivery for small ones.
function oneByteWrites(data: Uint8Array, cap = Infinity): Uint8Array[] {
  const n = Math.min(data.length, cap);
  const pieces = Array.from({ length: n }, (_, i) => data.subarray(i, i + 1));
  if (n < data.length) pieces.push(data.subarray(n));
  return pieces;
}

function chunkedWrites(data: Uint8Array, size: number): Uint8Array[] {
  const pieces: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += size) pieces.push(data.subarray(i, i + size));
  return pieces;
}

function splitAt(data: Uint8Array, n: number): Uint8Array[] {
  return [data.subarray(0, n), data.subarray(n)];
}

function prefixByteWrites(data: Uint8Array, n: number): Uint8Array[] {
  const pieces = Array.from({ length: n }, (_, i) => data.subarray(i, i + 1));
  pieces.push(data.subarray(n));
  return pieces;
}

// Drives a freshly-constructed stream: writes each piece, closes, and
// collects everything read — with reading running concurrently with
// writing so backpressure on large/many-piece inputs can't deadlock it.
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

async function collect(readable: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = readable.getReader();
  const chunks: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(...chunks);
}

function randomKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(cobblestone128.KEY_SIZE));
}

describe("encrypt input-delivery variants (Go: readerVariants OneByteReader/HalfReader)", () => {
  it.each([0, 7, 16384, 16385, 40000])(
    "round-trips a %d-byte plaintext through every write pattern",
    async (size) => {
      const key = randomKey();
      const plaintext = fillPattern(size);
      const patterns: Uint8Array[][] = [
        oneWrite(plaintext),
        oneByteWrites(plaintext, size === 40000 ? 4096 : Infinity),
        chunkedWrites(plaintext, 8191),
        chunkedWrites(plaintext, CHUNK_SIZE),
      ];

      for (const pieces of patterns) {
        const { delivered, error } = await drive(new cobblestone128.EncryptionStream(key), pieces);
        expect(error).toBeUndefined();
        expect(await cobblestone128.decrypt(key, delivered)).toEqual(plaintext);
      }
    },
  );
});

describe("decrypt input-delivery variants (Go: readerVariants OneByteReader/HalfReader)", () => {
  const DECRYPT_SPLIT_PATTERNS: [string, (ct: Uint8Array) => Uint8Array[]][] = [
    ["single write", (ct) => oneWrite(ct)],
    ["57-then-rest (straddles header+chunk boundary)", (ct) => splitAt(ct, 57)],
    ["1-byte writes for the first 100 bytes then the rest", (ct) => prefixByteWrites(ct, 100)],
  ];

  it.each(DECRYPT_SPLIT_PATTERNS)("decrypts correctly with %s", async (_label, split) => {
    const key = randomKey();
    const plaintext = fillPattern(20000);
    const ciphertext = await cobblestone128.encrypt(key, plaintext);

    const { delivered, error } = await drive(
      new cobblestone128.DecryptionStream(key),
      split(ciphertext),
    );
    expect(error).toBeUndefined();
    expect(delivered).toEqual(plaintext);
  });
});

describe("erroring source (Go: brokenReader + checkSrcError)", () => {
  it("rejects with the exact source error through DecryptionStream, not a CobblestoneError or clean EOF", async () => {
    const key = randomKey();
    const ciphertext = await cobblestone128.encrypt(key, fillPattern(40000));
    const err = new Error("simulated source error");
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(ciphertext.subarray(0, Math.floor(ciphertext.length / 2)));
        controller.error(err);
      },
    });

    let caught: unknown;
    try {
      await collect(source.pipeThrough(new cobblestone128.DecryptionStream(key)));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBe(err);
    expect(caught).not.toBeInstanceOf(cobblestone128.CobblestoneError);
  });

  it("rejects with the exact source error through EncryptionStream, not a CobblestoneError or clean EOF", async () => {
    const key = randomKey();
    const plaintext = fillPattern(40000);
    const err = new Error("simulated source error");
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(plaintext.subarray(0, Math.floor(plaintext.length / 2)));
        controller.error(err);
      },
    });

    let caught: unknown;
    try {
      await collect(source.pipeThrough(new cobblestone128.EncryptionStream(key)));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBe(err);
    expect(caught).not.toBeInstanceOf(cobblestone128.CobblestoneError);
  });
});

describe("error persistence (Go: checkErrorPersistence)", () => {
  it("keeps rejecting reads and writes after the first authentication failure", async () => {
    const key = randomKey();
    const ciphertext = await cobblestone128.encrypt(key, fillPattern(40000));
    const corrupted = flipByte(ciphertext, 60);

    const stream = new cobblestone128.DecryptionStream(key);
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    const firstWrite = writer.write(corrupted).catch((e: unknown) => e);

    const firstRead = await reader.read().catch((e: unknown) => e);
    expect(firstRead).toBeInstanceOf(cobblestone128.AuthenticationError);

    const secondRead = await reader.read().catch((e: unknown) => e);
    expect(secondRead).toBeInstanceOf(Error);

    const writeAfter = await writer.write(new Uint8Array(1)).catch((e: unknown) => e);
    expect(writeAfter).toBeInstanceOf(Error);

    const closeAfter = await writer.close().catch((e: unknown) => e);
    expect(closeAfter).toBeInstanceOf(Error);

    await firstWrite;
  });

  it("resolves {done: true} repeatedly after a clean full decrypt", async () => {
    const key = randomKey();
    const ciphertext = await cobblestone128.encrypt(key, fillPattern(1000));
    const stream = new cobblestone128.DecryptionStream(key);
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();

    const writeDone = (async () => {
      await writer.write(ciphertext);
      await writer.close();
    })();

    for (;;) {
      const { done } = await reader.read();
      if (done) break;
    }
    await writeDone;

    expect(await reader.read()).toEqual({ done: true, value: undefined });
    expect(await reader.read()).toEqual({ done: true, value: undefined });
  });
});

describe("write-after-close (Go: EncryptWriter double-Close)", () => {
  it("rejects a write after close, and rejects a second close", async () => {
    const key = randomKey();
    const stream = new cobblestone128.EncryptionStream(key);
    const writer = stream.writable.getWriter();

    await writer.close();
    await expect(writer.write(new Uint8Array(1))).rejects.toThrow();
    await expect(writer.close()).rejects.toThrow();
  });
});
