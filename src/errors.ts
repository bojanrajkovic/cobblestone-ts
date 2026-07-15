export class CobblestoneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CobblestoneError";
  }
}

export class InvalidKeyError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidKeyError";
  }
}

export class CommitmentMismatchError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "CommitmentMismatchError";
  }
}

export class AuthenticationError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class TruncationError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "TruncationError";
  }
}

export class InvalidSizeError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSizeError";
  }
}

export class CounterOverflowError extends CobblestoneError {
  constructor(message: string) {
    super(message);
    this.name = "CounterOverflowError";
  }
}
