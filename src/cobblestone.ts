// Internal factory for the high-level Cobblestone API. Instantiated once per
// AEAD size by cobblestone-128.ts and cobblestone-256.ts — not exported from
// the package directly.

import { aesGcm } from "./internal/aes-gcm.js";
import { concat, constantTimeEqual, utf8 } from "./internal/bytes.js";
import { type AeadDescriptor, deriveMessageParams } from "./internal/derive.js";
import {
  CHUNK_OVERHEAD,
  CHUNK_SIZE,
  decryptTransformer,
  encryptTransformer,
  MAX_CHUNKS,
  normalizeSource,
  openRawReader,
  plaintextSize as chunkPlaintextSize,
  sectionSource,
} from "./internal/engine.js";
import type { ByteRangeSource, DecryptingReader } from "./internal/engine.js";
import {
  CommitmentMismatchError,
  InvalidKeyError,
  InvalidSizeError,
  TruncationError,
} from "./errors.js";

const HEADER_SIZE = 56;
const SALT_SIZE = 24;

export interface CobblestoneOptions {
  context?: string | Uint8Array;
}

export interface CobblestoneInstance {
  readonly KEY_SIZE: number;
  encrypt(key: Uint8Array, plaintext: Uint8Array, opts?: CobblestoneOptions): Promise<Uint8Array>;
  decrypt(key: Uint8Array, ciphertext: Uint8Array, opts?: CobblestoneOptions): Promise<Uint8Array>;
  readonly EncryptionStream: new (
    key: Uint8Array,
    opts?: CobblestoneOptions,
  ) => TransformStream<Uint8Array, Uint8Array>;
  readonly DecryptionStream: new (
    key: Uint8Array,
    opts?: CobblestoneOptions,
  ) => TransformStream<Uint8Array, Uint8Array>;
  openDecryptingReader(
    key: Uint8Array,
    source: Blob | ByteRangeSource,
    opts?: CobblestoneOptions,
  ): Promise<DecryptingReader>;
  plaintextSize(n: number): number;
  ciphertextSize(n: number): number;
}

function normalizeContext(context: string | Uint8Array | undefined): Uint8Array {
  if (context === undefined) return new Uint8Array(0);
  return typeof context === "string" ? utf8(context) : context;
}

async function collect(readable: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const reader = readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(...chunks);
}

// Drains a freshly-constructed stream with a single write, propagating
// exactly one error however either side fails. The collector is attached
// before the write starts, so backpressure never stalls the pipe.
async function runOneShot(
  stream: TransformStream<Uint8Array, Uint8Array>,
  input: Uint8Array,
): Promise<Uint8Array> {
  const writer = stream.writable.getWriter();
  const output = collect(stream.readable);
  const written = writer.write(input).then(() => writer.close());

  const [outputResult, writtenResult] = await Promise.allSettled([output, written]);
  if (outputResult.status === "rejected") throw outputResult.reason;
  if (writtenResult.status === "rejected") throw writtenResult.reason;
  return outputResult.value;
}

export function makeCobblestone(d: AeadDescriptor): CobblestoneInstance {
  class EncryptionStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(key: Uint8Array, opts?: CobblestoneOptions) {
      if (key.length !== d.keySize) {
        throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
      }
      const context = normalizeContext(opts?.context);
      let inner: ReturnType<typeof encryptTransformer> | undefined;

      super({
        async start(controller) {
          const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
          const { aeadKey, baseNonce, commitment } = await deriveMessageParams(
            d,
            key,
            salt,
            context,
          );
          const aead = await aesGcm(aeadKey);
          controller.enqueue(concat(salt, commitment));
          inner = encryptTransformer(aead, baseNonce);
        },
        transform(chunk, controller) {
          // start() always resolves before transform/flush run (Web Streams
          // spec gates writes on startPromise) — inner is always set here.
          return inner!.transform(chunk, controller);
        },
        flush(controller) {
          return inner!.flush(controller);
        },
      });
    }
  }

  class DecryptionStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(key: Uint8Array, opts?: CobblestoneOptions) {
      if (key.length !== d.keySize) {
        throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
      }
      const context = normalizeContext(opts?.context);
      let header: Uint8Array[] = [];
      let headerLength = 0;
      let inner: ReturnType<typeof decryptTransformer> | undefined;

      super({
        async transform(chunk, controller) {
          if (inner === undefined) {
            header.push(chunk);
            headerLength += chunk.length;
            if (headerLength < HEADER_SIZE) return;

            const joined = concat(...header);
            header = [];
            const salt = joined.subarray(0, SALT_SIZE);
            const commitment = joined.subarray(SALT_SIZE, HEADER_SIZE);
            const surplus = joined.subarray(HEADER_SIZE);

            const derived = await deriveMessageParams(d, key, salt, context);
            if (!constantTimeEqual(derived.commitment, commitment)) {
              throw new CommitmentMismatchError("derived commitment does not match header");
            }
            const aead = await aesGcm(derived.aeadKey);
            inner = decryptTransformer(aead, derived.baseNonce);
            if (surplus.length > 0) await inner.transform(surplus, controller);
            return;
          }
          await inner.transform(chunk, controller);
        },
        async flush(controller) {
          if (inner === undefined) {
            throw new TruncationError(`truncated header: ${headerLength} of ${HEADER_SIZE} bytes`);
          }
          await inner.flush(controller);
        },
      });
    }
  }

  async function openDecryptingReader(
    key: Uint8Array,
    source: Blob | ByteRangeSource,
    opts?: CobblestoneOptions,
  ): Promise<DecryptingReader> {
    if (key.length !== d.keySize) {
      throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${key.length}`);
    }
    const context = normalizeContext(opts?.context);
    const src = normalizeSource(source);
    if (src.size < HEADER_SIZE) {
      throw new InvalidSizeError(
        `source size ${src.size} is smaller than the ${HEADER_SIZE}-byte header`,
      );
    }

    const header = await src.readAt(0, HEADER_SIZE);
    if (header.length !== HEADER_SIZE) {
      throw new TruncationError(
        `short header read: expected ${HEADER_SIZE} bytes, got ${header.length}`,
      );
    }
    const salt = header.subarray(0, SALT_SIZE);
    const commitment = header.subarray(SALT_SIZE, HEADER_SIZE);

    const derived = await deriveMessageParams(d, key, salt, context);
    if (!constantTimeEqual(derived.commitment, commitment)) {
      throw new CommitmentMismatchError("derived commitment does not match header");
    }
    const aead = await aesGcm(derived.aeadKey);
    return openRawReader(aead, derived.baseNonce, sectionSource(src, HEADER_SIZE));
  }

  function plaintextSize(n: number): number {
    if (!Number.isSafeInteger(n) || n < 0) {
      throw new InvalidSizeError(`ciphertext size must be a non-negative safe integer, got ${n}`);
    }
    if (n < HEADER_SIZE) {
      throw new InvalidSizeError(
        `ciphertext size ${n} is smaller than the ${HEADER_SIZE}-byte header`,
      );
    }
    return chunkPlaintextSize(n - HEADER_SIZE);
  }

  function ciphertextSize(n: number): number {
    const maxPlaintext = MAX_CHUNKS * CHUNK_SIZE - 1;
    if (!Number.isSafeInteger(n) || n < 0 || n > maxPlaintext) {
      throw new InvalidSizeError(
        `plaintext size must be a safe integer in [0, ${maxPlaintext}], got ${n}`,
      );
    }
    return HEADER_SIZE + n + (Math.floor(n / CHUNK_SIZE) + 1) * CHUNK_OVERHEAD;
  }

  return {
    KEY_SIZE: d.keySize,
    // async, not a plain arrow returning runOneShot's promise: a bad key
    // size throws synchronously from `new EncryptionStream`/`DecryptionStream`,
    // and one-shots must reject rather than throw across the call.
    encrypt: async (key, plaintext, opts) => runOneShot(new EncryptionStream(key, opts), plaintext),
    decrypt: async (key, ciphertext, opts) =>
      runOneShot(new DecryptionStream(key, opts), ciphertext),
    EncryptionStream,
    DecryptionStream,
    openDecryptingReader,
    plaintextSize,
    ciphertextSize,
  };
}
