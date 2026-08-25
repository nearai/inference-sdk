export class VerificationError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
    this.name = 'VerificationError';
  }
}

export class CloudApiError extends VerificationError {
  constructor(
    message: string,
    readonly status?: number,
    cause?: unknown,
  ) {
    super(message, cause);
    this.name = 'CloudApiError';
  }
}
