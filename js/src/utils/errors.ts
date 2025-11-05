export class VerificationError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
    this.name = 'VerificationError';
  }
}
