/** Base class for every error this package throws. */
export class CobblestoneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CobblestoneError";
  }
}

/** A key isn't the length required by the AEAD or instantiation in use. */
export class InvalidKeyError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidKeyError";
  }
}

/** The commitment derived from a key/context doesn't match the ciphertext header. */
export class CommitmentMismatchError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "CommitmentMismatchError";
  }
}

/** An AEAD chunk failed to authenticate — corrupted or tampered ciphertext. */
export class AuthenticationError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

/** The ciphertext or header ended before a complete header or chunk was read. */
export class TruncationError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "TruncationError";
  }
}

/** A size argument — a source size, an offset/length, or size-math input — is out of range. */
export class InvalidSizeError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSizeError";
  }
}

/** The per-message chunk counter exceeded its 2^38 limit. */
export class CounterOverflowError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "CounterOverflowError";
  }
}
