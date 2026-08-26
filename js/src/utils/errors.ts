import type { TcbStatus } from '../types/verification';

/** A JSON-safe description of a verification failure.
 *
 * `code`, `phase`, and the fields in `details` are the public error contract.
 * `message` is only for people; consumers must not parse it. The shape is kept
 * deliberately free of API keys, nonces, quotes, prompts, and response bytes.
 * Future language SDKs should preserve these codes and detail field names.
 */
export type VerificationFailure =
  | {
      phase: 'input';
      code: 'input.invalid';
      details: {
        field: string;
        reason:
          | 'missing'
          | 'invalid_hex'
          | 'wrong_length'
          | 'invalid_json'
          | 'invalid_jwt'
          | 'invalid_url'
          | 'invalid_header'
          | 'unsupported_value';
        expected?: string;
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      phase: 'api';
      code: 'api.transport_failed';
      details: {
        operation: string;
        reason: 'request' | 'response_body';
      };
      retryable: true;
    }
  | {
      phase: 'api';
      code: 'api.http_status';
      details: {
        operation: string;
        status: number;
      };
      retryable: boolean;
    }
  | {
      phase: 'api';
      code: 'api.invalid_json';
      details: { operation: string };
    }
  | {
      phase: 'api';
      code: 'api.invalid_response';
      details: {
        path: string;
        expected: string;
        actual: string;
      };
    }
  | {
      phase: 'api';
      code: 'api.unexpected_model_attestation_count';
      details: { expectedCount: 1; actualCount: number };
    }
  | {
      phase: 'quote';
      code: 'quote.collateral_unavailable';
      details: Record<never, never>;
      retryable: true;
    }
  | {
      phase: 'quote';
      code: 'quote.verification_failed';
      details: { reason: 'invalid_encoding' | 'verifier_error' };
    }
  | {
      phase: 'quote';
      code: 'quote.invalid_result';
      details: {
        path: string;
        expected: string;
        actual: string;
      };
    }
  | {
      phase: 'quote';
      code: 'quote.unsupported_report_type';
      details: { expected: 'TD10' };
    }
  | {
      phase: 'policy';
      code: 'policy.debug_enabled';
      details: { target: 'near_model' | 'gateway' };
    }
  | {
      phase: 'policy';
      code: 'policy.tcb_status_not_allowed';
      details: {
        target: 'near_model' | 'gateway';
        actual: TcbStatus;
        allowed: readonly TcbStatus[];
        advisoryIds: readonly string[];
      };
    }
  | {
      phase: 'policy';
      code: 'policy.gpu_evidence_required';
      details: Record<never, never>;
    }
  | {
      phase: 'policy';
      code: 'policy.provenance_verifier_required';
      details: Record<never, never>;
    }
  | {
      phase: 'binding';
      code: 'binding.nonce_mismatch';
      details: {
        source: 'request_nonce' | 'quote_report_data' | 'nvidia_payload';
      };
    }
  | {
      phase: 'binding';
      code: 'binding.report_data_invalid';
      details: {
        source: 'quote_report_data' | 'advertised_report_data';
        reason: 'invalid_hex' | 'wrong_length';
        expectedBytes: 64;
        actualBytes?: number;
      };
    }
  | {
      phase: 'binding';
      code: 'binding.report_data_mismatch';
      details: {
        source:
          | 'advertised_report_data'
          | 'signer_binding'
          | 'signer_tls_binding';
      };
    }
  | {
      phase: 'binding';
      code: 'binding.tls_fingerprint_missing';
      details: { target: 'gateway' };
    }
  | {
      phase: 'binding';
      code: 'binding.tls_fingerprint_mismatch';
      details: { source: 'peer_tls_connection' };
    }
  | {
      phase: 'measurement';
      code: 'measurement.event_log_invalid';
      details: {
        path: string;
        reason:
          | 'invalid_json'
          | 'invalid_type'
          | 'invalid_hex'
          | 'wrong_length'
          | 'digest_mismatch';
        expected?: string;
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      phase: 'measurement';
      code: 'measurement.rtmr3_mismatch';
      details: {
        reason: 'wrong_length' | 'no_events' | 'replay_mismatch';
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      phase: 'measurement';
      code: 'measurement.app_compose_invalid';
      details: { reason: 'invalid_json' | 'missing' };
    }
  | {
      phase: 'measurement';
      code: 'measurement.mrconfigid_invalid';
      details: {
        reason: 'wrong_length' | 'unsupported_version';
        minimumBytes?: number;
        actualBytes?: number;
        version?: number;
      };
    }
  | {
      phase: 'measurement';
      code: 'measurement.app_compose_mrconfigid_mismatch';
      details: Record<never, never>;
    }
  | {
      phase: 'gpu';
      code: 'gpu.payload_invalid';
      details: { reason: 'invalid_json' | 'nonce_missing' };
    }
  | {
      phase: 'gpu';
      code: 'gpu.nras_request_failed';
      details: {
        reason: 'timeout' | 'transport' | 'http_status';
        status?: number;
      };
      retryable: boolean;
    }
  | {
      phase: 'gpu';
      code: 'gpu.nras_response_invalid';
      details: {
        reason:
          | 'invalid_json'
          | 'invalid_jwt'
          | 'invalid_schema'
          | 'invalid_verdict_type';
      };
    }
  | {
      phase: 'gpu';
      code: 'gpu.attestation_rejected';
      details: { source: 'nras' | 'custom_verifier' };
    }
  | {
      phase: 'provenance';
      code: 'provenance.verification_failed';
      details: Record<never, never>;
    }
  | {
      phase: 'signature';
      code: 'signature.unavailable';
      details: { providerErrorCode: string };
    }
  | {
      phase: 'signature';
      code: 'signature.unknown_kind';
      details: Record<never, never>;
    }
  | {
      phase: 'signature';
      code: 'signature.payload_mismatch';
      details: {
        source: 'request_model' | 'signed_payload';
        reason: 'invalid_json' | 'missing_model' | 'text_mismatch';
      };
    }
  | {
      phase: 'signature';
      code: 'signature.format_invalid';
      details: {
        field: 'signature' | 'signing_address' | 'signing_algo';
        reason: 'invalid_hex' | 'wrong_length' | 'unsupported_algorithm';
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      phase: 'signature';
      code: 'signature.invalid';
      details: { algorithm: 'ecdsa' | 'ed25519' };
    }
  | {
      phase: 'signature';
      code: 'signature.signer_mismatch';
      details: Record<never, never>;
    }
  | {
      phase: 'runtime';
      code: 'runtime.crypto_unavailable';
      details: { capability: 'subtle_digest' | 'secure_random' };
    };

export type VerificationErrorCode = VerificationFailure['code'];
export type VerificationPhase = VerificationFailure['phase'];
export type ApiFailure = Extract<VerificationFailure, { phase: 'api' }>;

export type VerificationErrorOptions = { cause?: unknown };

/**
 * A machine-readable verification failure.
 *
 * Inspect `failure.code` (and, where needed, its typed `details`) instead of
 * branching on `message`. This is intentionally a single class: the
 * discriminated `failure` union gives TypeScript and future SDKs a stable,
 * cross-language contract without requiring a class hierarchy per failure.
 */
export class VerificationError extends Error {
  readonly name: string = 'VerificationError';

  constructor(
    readonly failure: VerificationFailure,
    options?: VerificationErrorOptions,
  ) {
    super(formatFailureMessage(failure), options);
  }

  get code(): VerificationErrorCode {
    return this.failure.code;
  }

  get phase(): VerificationPhase {
    return this.failure.phase;
  }

  get details(): VerificationFailure['details'] {
    return this.failure.details;
  }

  get retryable(): boolean {
    return 'retryable' in this.failure && this.failure.retryable;
  }

  /** Safe structured data for logs and cross-process diagnostics. */
  toJSON(): {
    name: string;
    message: string;
    failure: VerificationFailure;
    retryable: boolean;
  } {
    return {
      name: this.name,
      message: this.message,
      failure: this.failure,
      retryable: this.retryable,
    };
  }
}

/** API transport or response failure; inspect `failure.code` as usual. */
export class ApiError extends VerificationError {
  readonly name: string = 'ApiError';

  // biome-ignore lint/complexity/noUselessConstructor: Narrows the public input to API failures.
  constructor(failure: ApiFailure, options?: VerificationErrorOptions) {
    super(failure, options);
  }

  /** Kept as a convenience for HTTP callers; `failure.details.status` is canonical. */
  get status(): number | undefined {
    return this.failure.code === 'api.http_status'
      ? this.failure.details.status
      : undefined;
  }
}

export function isVerificationError(
  value: unknown,
): value is VerificationError {
  return value instanceof VerificationError;
}

/** Preserve an SDK failure, or add a stable failure code around an external cause. */
export function wrapVerificationError(
  failure: VerificationFailure,
  cause: unknown,
): VerificationError {
  return isVerificationError(cause)
    ? cause
    : new VerificationError(failure, { cause });
}

function formatFailureMessage(failure: VerificationFailure): string {
  switch (failure.code) {
    case 'input.invalid':
      return `Invalid ${failure.details.field}`;
    case 'api.transport_failed':
      return 'API request failed';
    case 'api.http_status':
      return `API returned HTTP ${failure.details.status}`;
    case 'api.invalid_json':
      return 'API returned invalid JSON';
    case 'api.invalid_response':
      return `API response has an invalid ${failure.details.path} field`;
    case 'api.unexpected_model_attestation_count':
      return 'API returned an unexpected number of model attestations';
    case 'quote.collateral_unavailable':
      return 'Intel collateral is unavailable';
    case 'quote.verification_failed':
      return 'Intel TDX quote verification failed';
    case 'quote.invalid_result':
      return `Quote verifier returned an invalid ${failure.details.path} field`;
    case 'quote.unsupported_report_type':
      return 'Verified quote has an unsupported report type';
    case 'policy.debug_enabled':
      return 'TDX debug mode is enabled';
    case 'policy.tcb_status_not_allowed':
      return 'TDX TCB status is not allowed by policy';
    case 'policy.gpu_evidence_required':
      return 'GPU evidence is required by policy';
    case 'policy.provenance_verifier_required':
      return 'Deployment provenance verification is required by policy';
    case 'binding.nonce_mismatch':
      return 'Attestation nonce does not match';
    case 'binding.report_data_invalid':
      return 'Attestation report data is invalid';
    case 'binding.report_data_mismatch':
      return 'Attestation report data does not match the verified quote';
    case 'binding.tls_fingerprint_missing':
      return 'Attestation is missing its TLS fingerprint';
    case 'binding.tls_fingerprint_mismatch':
      return 'Attestation TLS fingerprint does not match the peer connection';
    case 'measurement.event_log_invalid':
      return 'Attestation event log is invalid';
    case 'measurement.rtmr3_mismatch':
      return 'Attestation event log does not match RTMR3';
    case 'measurement.app_compose_invalid':
      return 'Attestation app compose data is invalid';
    case 'measurement.mrconfigid_invalid':
      return 'Quote MRCONFIGID is invalid';
    case 'measurement.app_compose_mrconfigid_mismatch':
      return 'App compose does not match quote MRCONFIGID';
    case 'gpu.payload_invalid':
      return 'GPU evidence payload is invalid';
    case 'gpu.nras_request_failed':
      return 'NVIDIA NRAS request failed';
    case 'gpu.nras_response_invalid':
      return 'NVIDIA NRAS response is invalid';
    case 'gpu.attestation_rejected':
      return 'NVIDIA NRAS rejected GPU attestation';
    case 'provenance.verification_failed':
      return 'Deployment provenance verification failed';
    case 'signature.unavailable':
      return 'Completion signature is unavailable';
    case 'signature.unknown_kind':
      return 'Completion signature kind is missing or unsupported';
    case 'signature.payload_mismatch':
      return 'Completion signature does not match the request or response';
    case 'signature.format_invalid':
      return 'Completion signature format is invalid';
    case 'signature.invalid':
      return 'Completion signature is invalid';
    case 'signature.signer_mismatch':
      return 'Completion signature signer does not match the attestation';
    case 'runtime.crypto_unavailable':
      return 'Required Web Crypto capability is unavailable';
  }
}
