declare const verificationContextBrand: unique symbol;

/** Public Intel material shared within one verification operation, never verdicts. */
export type VerificationContext = {
  readonly [verificationContextBrand]: true;
};

export type CreateVerificationContextParams = {
  /** Transport for Intel collateral GETs only. Defaults to globalThis.fetch. */
  readonly fetch?: typeof globalThis.fetch;
};

export type QuoteVerificationOptions = {
  /** Share this context across related Gateway, model and direct checks. */
  readonly context?: VerificationContext;
  /** Cancels this consumer without cancelling another consumer's download. */
  readonly signal?: AbortSignal;
};
