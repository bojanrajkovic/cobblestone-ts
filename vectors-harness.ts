import { concat, hexToBytes } from "./src/internal/bytes.js";

export interface Vector {
  tcId: number;
  comment: string;
  key: Uint8Array;
  ctxBytes: Uint8Array;
  ct: Uint8Array; // inflated
  aeadKey?: Uint8Array | undefined;
  baseNonce?: Uint8Array | undefined;
  msgLength?: number | undefined;
  msgSha512?: Uint8Array | undefined;
  result: string;
  flags: string[];
}

interface RawTest {
  tcId: number;
  comment: string;
  key: string;
  ctx: string;
  ct: string;
  aeadKey?: string;
  baseNonce?: string;
  msgLength?: number;
  msgSha512?: string;
  result: string;
  flags: string[];
}

interface RawVectorFile {
  testGroups: { tests: RawTest[] }[];
}

// `ct` is hex of zlib(deflate)-compressed ciphertext, not raw deflate — 'deflate'
// selects the zlib container; 'deflate-raw' would silently corrupt the output.
async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new DecompressionStream("deflate");
  const writer = stream.writable.getWriter();
  void writer.write(bytes);
  void writer.close();

  const chunks: Uint8Array[] = [];
  const reader = stream.readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(...chunks);
}

// Takes the already-parsed vector JSON (static `import` of the testdata
// file) instead of a path — keeps this harness free of node:fs so it runs
// under vitest on any runtime, including browser mode.
export async function loadVectors(rawFile: unknown): Promise<Vector[]> {
  const raw = rawFile as RawVectorFile;
  const vectors: Vector[] = [];

  for (const group of raw.testGroups) {
    for (const t of group.tests) {
      const ct = await inflate(hexToBytes(t.ct));

      // Verify gate: an empty message is header (56 bytes) + one sealed
      // empty chunk (16 bytes overhead) = 72 bytes. If this drifts, the
      // inflation above is producing the wrong bytes.
      if (t.tcId === 1 && ct.byteLength !== 72) {
        throw new Error(
          `vector harness inflation check failed: tc1 inflated to ${ct.byteLength} bytes, expected 72`,
        );
      }

      vectors.push({
        tcId: t.tcId,
        comment: t.comment,
        key: hexToBytes(t.key),
        ctxBytes: hexToBytes(t.ctx),
        ct,
        aeadKey: t.aeadKey === undefined ? undefined : hexToBytes(t.aeadKey),
        baseNonce: t.baseNonce === undefined ? undefined : hexToBytes(t.baseNonce),
        msgLength: t.msgLength,
        msgSha512: t.msgSha512 === undefined ? undefined : hexToBytes(t.msgSha512),
        result: t.result,
        flags: t.flags,
      });
    }
  }

  return vectors;
}
