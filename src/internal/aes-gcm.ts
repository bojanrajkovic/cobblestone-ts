import { AuthenticationError, InvalidKeyError } from "../errors.js";

export interface Aead {
  readonly nonceSize: number;
  readonly overhead: 16;
  seal(nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  open(nonce: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
}

export async function aesGcm(key: Uint8Array): Promise<Aead> {
  if (key.length !== 16 && key.length !== 32) {
    throw new InvalidKeyError(`key must be 16 or 32 bytes, got ${key.length}`);
  }

  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);

  return {
    nonceSize: 12,
    overhead: 16,
    async seal(nonce, plaintext) {
      const sealed = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        cryptoKey,
        plaintext,
      );
      return new Uint8Array(sealed);
    },
    async open(nonce, ciphertext) {
      try {
        const opened = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: nonce },
          cryptoKey,
          ciphertext,
        );
        return new Uint8Array(opened);
      } catch {
        // Never leak the DOMException — callers only see our error types.
        throw new AuthenticationError("AES-GCM authentication failed");
      }
    },
  };
}
