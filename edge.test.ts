// Edge-case hardening suite, porting the intent of the Go reference
// implementation's edge tests. Each describe block names the Go ancestor
// it's standing in for.

import { beforeAll, describe, expect, it } from "vitest";

// Plain-setTimeout delay instead of node:timers/promises — works in
// browser-mode vitest runs too.
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
import * as cobblestone128 from "./src/cobblestone-128.js";
import * as cobblestone256 from "./src/cobblestone-256.js";
import { CHUNK_SIZE } from "./src/internal/engine.js";
import type { ByteRangeSource } from "./src/internal/engine.js";
import { concat, utf8 } from "./src/internal/bytes.js";

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

function byteRangeSource(data: Uint8Array): ByteRangeSource {
  return {
    size: data.length,
    readAt: (offset, length) => Promise.resolve(data.subarray(offset, offset + length)),
  };
}

// Honest about `size`, but every readAt() past the `honestCalls`-th call
// returns 10 fewer bytes than requested — for pinning down exactly which
// short read site (header, eager final-chunk, or a later user readAt)
// surfaces TruncationError.
function lyingByteRangeSource(data: Uint8Array, honestCalls: number): ByteRangeSource {
  let calls = 0;
  return {
    size: data.length,
    readAt(offset, length) {
      calls++;
      const actualLength = calls <= honestCalls ? length : Math.max(0, length - 10);
      return Promise.resolve(data.subarray(offset, offset + actualLength));
    },
  };
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

// KEY_SIZE is a literal (16 vs 32) on each module, so `typeof cobblestone128`
// itself isn't a common type for both — widen just the fields this sweep uses.
interface CobblestoneModule {
  KEY_SIZE: number;
  encrypt: typeof cobblestone128.encrypt;
  decrypt: typeof cobblestone128.decrypt;
  ciphertextSize: typeof cobblestone128.ciphertextSize;
  plaintextSize: typeof cobblestone128.plaintextSize;
}

const MODULES: [string, CobblestoneModule][] = [
  ["cobblestone-128", cobblestone128],
  ["cobblestone-256", cobblestone256],
];

describe.each(MODULES)(
  "boundary round-trips (Go: TestRoundTrip size sweep) — %s",
  (_label, mod) => {
    it.each([0, 1, 15, 16, 16383, 16384, 16385, 32767, 32768, 32769, 65536, 100000])(
      "round-trips a %d-byte plaintext",
      async (size) => {
        const key = crypto.getRandomValues(new Uint8Array(mod.KEY_SIZE));
        const plaintext = fillPattern(size);
        const ciphertext = await mod.encrypt(key, plaintext);

        expect(ciphertext.length).toBe(mod.ciphertextSize(size));
        expect(mod.plaintextSize(ciphertext.length)).toBe(size);
        expect(await mod.decrypt(key, ciphertext)).toEqual(plaintext);
      },
    );
  },
);

describe("context binding (Go: TestContext, TestWrongKey)", () => {
  const plaintext = fillPattern(1000);

  const CONTEXT_VARIANTS: [string, string | Uint8Array][] = [
    ["a string context", "some context"],
    ["a Uint8Array context", utf8("some context")],
    ["a string context containing a space", "some context with spaces"],
  ];

  it.each(CONTEXT_VARIANTS)("round-trips with %s", async (_label, context) => {
    const key = randomKey();
    const ciphertext = await cobblestone128.encrypt(key, plaintext, { context });
    expect(await cobblestone128.decrypt(key, ciphertext, { context })).toEqual(plaintext);
  });

  it("treats a string context and its UTF-8-equivalent Uint8Array as the same context", async () => {
    const key = randomKey();

    const ciphertextFromString = await cobblestone128.encrypt(key, plaintext, { context: "a" });
    expect(
      await cobblestone128.decrypt(key, ciphertextFromString, { context: new Uint8Array([0x61]) }),
    ).toEqual(plaintext);

    const ciphertextFromBytes = await cobblestone128.encrypt(key, plaintext, {
      context: new Uint8Array([0x61]),
    });
    expect(await cobblestone128.decrypt(key, ciphertextFromBytes, { context: "a" })).toEqual(
      plaintext,
    );
  });

  it("rejects CommitmentMismatchError for the wrong context", async () => {
    const key = randomKey();
    const ciphertext = await cobblestone128.encrypt(key, plaintext, { context: "right" });
    await expect(
      cobblestone128.decrypt(key, ciphertext, { context: "wrong" }),
    ).rejects.toBeInstanceOf(cobblestone128.CommitmentMismatchError);
  });

  it("rejects CommitmentMismatchError for the wrong key (same length)", async () => {
    const key = randomKey();
    const wrongKey = randomKey();
    const ciphertext = await cobblestone128.encrypt(key, plaintext);
    await expect(cobblestone128.decrypt(wrongKey, ciphertext)).rejects.toBeInstanceOf(
      cobblestone128.CommitmentMismatchError,
    );
  });

  it("treats an omitted context as equivalent to an empty context", async () => {
    const key = randomKey();

    const ciphertextOmitted = await cobblestone128.encrypt(key, plaintext);
    expect(
      await cobblestone128.decrypt(key, ciphertextOmitted, { context: new Uint8Array(0) }),
    ).toEqual(plaintext);

    const ciphertextEmpty = await cobblestone128.encrypt(key, plaintext, {
      context: new Uint8Array(0),
    });
    expect(await cobblestone128.decrypt(key, ciphertextEmpty)).toEqual(plaintext);
  });
});

describe("random-access reads (Go: TestDecryptReaderAt* family)", () => {
  const FIXTURE_SIZE = 53552; // 3 full 16384-byte chunks + 4400
  let key: Uint8Array;
  let plaintext: Uint8Array;
  let ciphertext: Uint8Array;

  beforeAll(async () => {
    key = randomKey();
    plaintext = fillPattern(FIXTURE_SIZE);
    ciphertext = await cobblestone128.encrypt(key, plaintext);
  });

  describe("boundary offsets and lengths", () => {
    it.each([0, 1, 16383, 16384, 16385, 49152, FIXTURE_SIZE - 1, FIXTURE_SIZE])(
      "offset %d matches the plaintext slice for every length variant",
      async (offset) => {
        const reader = await cobblestone128.openDecryptingReader(key, byteRangeSource(ciphertext));
        const lengths = [0, 1, 16, 20000, FIXTURE_SIZE - offset, FIXTURE_SIZE * 2];

        for (const length of lengths) {
          const result = await reader.readAt(offset, length);
          const expectedLength = Math.max(0, Math.min(length, FIXTURE_SIZE - offset));
          expect(result).toEqual(plaintext.subarray(offset, offset + expectedLength));
        }
      },
    );
  });

  describe("invalid offsets and lengths", () => {
    it("rejects InvalidSizeError for offset past size+1, negative offset/length, and a fractional offset", async () => {
      const reader = await cobblestone128.openDecryptingReader(key, byteRangeSource(ciphertext));
      await expect(reader.readAt(FIXTURE_SIZE + 1, 1)).rejects.toBeInstanceOf(
        cobblestone128.InvalidSizeError,
      );
      await expect(reader.readAt(-1, 1)).rejects.toBeInstanceOf(cobblestone128.InvalidSizeError);
      await expect(reader.readAt(0, -1)).rejects.toBeInstanceOf(cobblestone128.InvalidSizeError);
      await expect(reader.readAt(0.5, 1)).rejects.toBeInstanceOf(cobblestone128.InvalidSizeError);
    });

    it("plaintextSize/ciphertextSize reject impossible sizes with InvalidSizeError", () => {
      expect(() => cobblestone128.plaintextSize(-1)).toThrow(cobblestone128.InvalidSizeError);
      expect(() => cobblestone128.ciphertextSize(-1)).toThrow(cobblestone128.InvalidSizeError);
      expect(() => cobblestone128.ciphertextSize(2 ** 53)).toThrow(cobblestone128.InvalidSizeError);
    });
  });

  describe("cache patterns (correctness only, no timing)", () => {
    it("sequential reads within the same chunk stay correct", async () => {
      const reader = await cobblestone128.openDecryptingReader(key, byteRangeSource(ciphertext));
      for (const offset of [0, 100, 200, 5000, 16000]) {
        expect(await reader.readAt(offset, 50)).toEqual(plaintext.subarray(offset, offset + 50));
      }
    });

    it("alternating reads between chunk 0 and chunk 2 stay correct", async () => {
      const reader = await cobblestone128.openDecryptingReader(key, byteRangeSource(ciphertext));
      const spans: [number, number][] = [
        [100, 50],
        [32768 + 100, 50],
        [200, 50],
        [32768 + 200, 50],
      ];
      for (const [offset, length] of spans) {
        expect(await reader.readAt(offset, length)).toEqual(
          plaintext.subarray(offset, offset + length),
        );
      }
    });

    it("a full-file read after a 1-byte read is correct", async () => {
      const reader = await cobblestone128.openDecryptingReader(key, byteRangeSource(ciphertext));
      await reader.readAt(0, 1);
      expect(await reader.readAt(0, FIXTURE_SIZE)).toEqual(plaintext);
    });
  });

  describe("empty message", () => {
    it("reports plaintextSize 0 and readAt returns empty", async () => {
      const emptyKey = randomKey();
      const emptyCiphertext = await cobblestone128.encrypt(emptyKey, new Uint8Array(0));
      const reader = await cobblestone128.openDecryptingReader(
        emptyKey,
        byteRangeSource(emptyCiphertext),
      );
      expect(reader.plaintextSize).toBe(0);
      expect(await reader.readAt(0, 1)).toEqual(new Uint8Array(0));
    });
  });

  describe("corruption (Go: TestDecryptReaderAtCorrupted)", () => {
    it("opens successfully (final chunk valid) and confines the failure to chunk 1", async () => {
      const corrupted = flipByte(ciphertext, 56 + 16400 + 100);
      const reader = await cobblestone128.openDecryptingReader(key, byteRangeSource(corrupted));

      expect(await reader.readAt(0, CHUNK_SIZE)).toEqual(plaintext.subarray(0, CHUNK_SIZE));
      expect(await reader.readAt(2 * CHUNK_SIZE, FIXTURE_SIZE - 2 * CHUNK_SIZE)).toEqual(
        plaintext.subarray(2 * CHUNK_SIZE),
      );
      await expect(reader.readAt(CHUNK_SIZE, 100)).rejects.toBeInstanceOf(
        cobblestone128.AuthenticationError,
      );
    });

    // The 4416-byte final chunk stays arithmetically plausible with 10 bytes
    // shaved off (4406 is still a legal sealed-chunk length) — it reads as a
    // genuine, just-shorter message, so the eager final-chunk decrypt is
    // what catches it, not the size arithmetic.
    it("rejects AuthenticationError when truncated by 10 bytes (still arithmetically plausible)", async () => {
      const truncated = ciphertext.subarray(0, ciphertext.length - 10);
      await expect(
        cobblestone128.openDecryptingReader(key, byteRangeSource(truncated)),
      ).rejects.toBeInstanceOf(cobblestone128.AuthenticationError);
    });

    it("rejects InvalidSizeError when exactly the final 4416-byte chunk is dropped (ends on a full-chunk boundary)", async () => {
      const truncated = ciphertext.subarray(0, ciphertext.length - 4416);
      await expect(
        cobblestone128.openDecryptingReader(key, byteRangeSource(truncated)),
      ).rejects.toBeInstanceOf(cobblestone128.InvalidSizeError);
    });
  });

  describe("short-read sites (a lying ByteRangeSource, honest size, 10 bytes short per read)", () => {
    it("(a) short from the first (header) read -> TruncationError, not CommitmentMismatchError", async () => {
      await expect(
        cobblestone128.openDecryptingReader(key, lyingByteRangeSource(ciphertext, 0)),
      ).rejects.toBeInstanceOf(cobblestone128.TruncationError);
    });

    it("(b) honest header, short on the eager final-chunk read -> TruncationError", async () => {
      await expect(
        cobblestone128.openDecryptingReader(key, lyingByteRangeSource(ciphertext, 1)),
      ).rejects.toBeInstanceOf(cobblestone128.TruncationError);
    });

    it("(c) honest during open, short on a subsequent readAt -> TruncationError", async () => {
      const reader = await cobblestone128.openDecryptingReader(
        key,
        lyingByteRangeSource(ciphertext, 2),
      );
      await expect(reader.readAt(0, 1)).rejects.toBeInstanceOf(cobblestone128.TruncationError);
    });
  });

  describe("concurrent random access (Go: TestDecryptReaderAtConcurrent)", () => {
    it("resolves overlapping readAt spans correctly, including on a warm cache", async () => {
      const delayedSource: ByteRangeSource = {
        size: ciphertext.length,
        async readAt(offset, length) {
          await delay(1);
          return ciphertext.subarray(offset, offset + length);
        },
      };
      const reader = await cobblestone128.openDecryptingReader(key, delayedSource);

      const spans: [number, number][] = [
        [0, 100],
        [50, 200], // overlaps the previous span, same chunk
        [16384, 500],
        [16400, 300], // overlaps the previous span, same chunk
        [32768, 1000],
        [40000, 2000],
        [49152, 4000],
        [FIXTURE_SIZE - 10, 10],
      ];

      async function runBatch(): Promise<void> {
        await Promise.all(
          spans.map(async ([offset, length]) => {
            const result = await reader.readAt(offset, length);
            expect(result).toEqual(plaintext.subarray(offset, offset + length));
          }),
        );
      }

      await runBatch();
      await runBatch(); // cache warm
    });
  });
});
