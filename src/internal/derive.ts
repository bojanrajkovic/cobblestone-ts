import { concat, utf8 } from "./bytes.js";
import { InvalidKeyError, InvalidSizeError } from "../errors.js";
import { hkdfExpandSha512 } from "./hkdf.js";

const INFO_PREFIX = "c2sp.org/chunked-encryption@v1+";
const SALT_SIZE = 24;
const COMMITMENT_SIZE = 32;

export interface AeadDescriptor {
  readonly ianaName: string;
  readonly keySize: 16 | 32;
}

export const AES_128_GCM: AeadDescriptor = { ianaName: "AEAD_AES_128_GCM", keySize: 16 };
export const AES_256_GCM: AeadDescriptor = { ianaName: "AEAD_AES_256_GCM", keySize: 32 };

export interface MessageParams {
  aeadKey: Uint8Array;
  baseNonce: Uint8Array;
  commitment: Uint8Array;
}

export async function deriveMessageParams(
  d: AeadDescriptor,
  inputKey: Uint8Array,
  salt: Uint8Array,
  context: string | Uint8Array,
): Promise<MessageParams> {
  if (inputKey.length !== d.keySize) {
    throw new InvalidKeyError(`key must be ${d.keySize} bytes, got ${inputKey.length}`);
  }
  if (salt.length !== SALT_SIZE) {
    throw new InvalidSizeError(`salt must be ${SALT_SIZE} bytes, got ${salt.length}`);
  }

  const contextBytes = typeof context === "string" ? utf8(context) : context;
  const info = concat(
    utf8(INFO_PREFIX),
    utf8(d.ianaName),
    new Uint8Array([0x00]),
    salt,
    contextBytes,
  );
  const out = await hkdfExpandSha512(inputKey, info, d.keySize + 12 + COMMITMENT_SIZE);

  return {
    aeadKey: out.subarray(0, d.keySize),
    baseNonce: out.subarray(d.keySize, d.keySize + 12),
    commitment: out.subarray(d.keySize + 12, d.keySize + 12 + COMMITMENT_SIZE),
  };
}
