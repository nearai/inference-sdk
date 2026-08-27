import type { TcbStatus } from '../types/verification';

type ApiResource =
  | 'model_attestation'
  | 'gateway_attestation'
  | 'completion_signature';

/** A JSON-safe description of a Cloud API failure.
 *
 * `code`, `phase`, and any fields in `details` are the public error contract.
 * `message` is only for people; consumers must not parse it. The shape is kept
 * deliberately free of API keys, nonces, quotes, prompts, and response bytes.
 * Future language SDKs should preserve these codes and detail field names.
 */
export type ApiFailure =
  | {
      phase: 'api';
      code: 'api.transport_failed';
      details: {
        resource: ApiResource;
        reason: 'request' | 'response_body';
      };
      retryable: true;
    }
  | {
      phase: 'api';
      code: 'api.http_status';
      details: {
        resource: ApiResource;
        status: number;
      };
      retryable: boolean;
    }
  | {
      phase: 'api';
      code: 'api.invalid_json';
      details: { resource: ApiResource };
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
      code: 'api.nonce_mismatch';
      details: {
        resource: 'model_attestation' | 'gateway_attestation';
      };
    }
  | {
      phase: 'api';
      code: 'api.unexpected_model_attestation_count';
      details: { expectedCount: 1; actualCount: number };
    }
  | {
      phase: 'api';
      code: 'api.ambiguous_model_attestation_signer';
      details: { matchingCount: number; totalCount: number };
    }
  | {
      phase: 'api';
      code: 'api.attestation_signer_mismatch';
      details: {
        resource: 'model_attestation';
      };
    };

/** A JSON-safe description of a local verification failure.
 *
 * `code`, `phase`, and any fields in `details` are the public error contract.
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
      phase: 'quote';
      code: 'quote.collateral_unavailable';
      retryable: true;
    }
  | {
      phase: 'quote';
      code: 'quote.verification_failed';
      details: {
        reason: 'invalid_encoding' | 'invalid_quote' | 'verifier_error';
      };
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
    }
  | {
      phase: 'policy';
      code: 'policy.tcb_status_not_allowed';
      details: {
        actual: TcbStatus;
        accepted: readonly TcbStatus[];
        advisoryIds: readonly string[];
      };
    }
  | {
      phase: 'policy';
      code: 'policy.gpu_evidence_required';
    }
  | {
      phase: 'binding';
      code: 'binding.nonce_mismatch';
      details: {
        source: 'attestationNonce' | 'quoteReportData' | 'nvidiaPayload';
      };
    }
  | {
      phase: 'binding';
      code: 'binding.report_data_invalid';
      details: {
        source: 'quoteReportData' | 'reportedQuoteData';
        reason: 'invalid_hex' | 'wrong_length';
        expectedBytes: 64;
        actualBytes?: number;
      };
    }
  | {
      phase: 'binding';
      code: 'binding.report_data_mismatch';
      details: {
        source: 'reportedQuoteData' | 'signerBinding' | 'signerTlsBinding';
      };
    }
  | {
      phase: 'binding';
      code: 'binding.spki_fingerprint_missing';
    }
  | {
      phase: 'binding';
      code: 'binding.spki_fingerprint_mismatch';
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
    }
  | {
      phase: 'signature';
      code: 'signature.unavailable';
      details: { providerErrorCode: string };
    }
  | {
      phase: 'signature';
      code: 'signature.kind_mismatch';
      details: {
        expected: 'provider_tee' | 'gateway';
        actual: 'provider_tee' | 'gateway';
      };
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
        field: 'signature' | 'signer.signingAddress' | 'signer.signingAlgo';
        reason: 'invalid_hex' | 'wrong_length' | 'unsupported_signing_algo';
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      phase: 'signature';
      code: 'signature.invalid';
      details: { signingAlgo: 'ecdsa' | 'ed25519' };
    }
  | {
      phase: 'signature';
      code: 'signature.signer_mismatch';
    }
  | {
      phase: 'runtime';
      code: 'runtime.crypto_unavailable';
      details: { capability: 'subtle_digest' | 'secure_random' };
    };

type SdkFailure = ApiFailure | VerificationFailure;

export type ApiErrorCode = ApiFailure['code'];
export type VerificationErrorCode = VerificationFailure['code'];
export type VerificationPhase = VerificationFailure['phase'];

export type SdkErrorOptions = { cause?: unknown };

/**
 * A machine-readable local verification failure.
 *
 * Inspect `failure.code` (and, where needed, its typed `details`) instead of
 * branching on `message`. This is intentionally a single class: the
 * discriminated `failure` union gives TypeScript and future SDKs a stable,
 * cross-language contract.
 */
export class VerificationError extends Error {
  readonly name: string = 'VerificationError';

  constructor(
    readonly failure: VerificationFailure,
    options?: SdkErrorOptions,
  ) {
    super(formatFailureMessage(failure), options);
  }

  get code(): VerificationErrorCode {
    return this.failure.code;
  }

  get phase(): VerificationPhase {
    return this.failure.phase;
  }

  get retryable(): boolean {
    return isRetryableFailure(this.failure);
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

/** Cloud API request, response, or evidence-selection failure. */
export class ApiError extends Error {
  readonly name: string = 'ApiError';

  constructor(
    readonly failure: ApiFailure,
    options?: SdkErrorOptions,
  ) {
    super(formatFailureMessage(failure), options);
  }

  get code(): ApiErrorCode {
    return this.failure.code;
  }

  get phase(): 'api' {
    return this.failure.phase;
  }

  get retryable(): boolean {
    return isRetryableFailure(this.failure);
  }

  /** Safe structured data for logs and cross-process diagnostics. */
  toJSON(): {
    name: string;
    message: string;
    failure: ApiFailure;
    retryable: boolean;
  } {
    return {
      name: this.name,
      message: this.message,
      failure: this.failure,
      retryable: this.retryable,
    };
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

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

/** Preserve a verification failure, or add a stable failure code around an external cause. */
export function wrapVerificationError(
  failure: VerificationFailure,
  cause: unknown,
): VerificationError {
  return isVerificationError(cause)
    ? cause
    : new VerificationError(failure, { cause });
}

function isRetryableFailure(failure: SdkFailure): boolean {
  return 'retryable' in failure && failure.retryable;
}

function formatFailureMessage(failure: SdkFailure): string {
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
    case 'api.nonce_mismatch':
      return 'API attestation nonce does not match the request';
    case 'api.unexpected_model_attestation_count':
      return 'API returned an unexpected number of model attestations';
    case 'api.ambiguous_model_attestation_signer':
      return 'More than one model attestation matches the requested signer';
    case 'api.attestation_signer_mismatch':
      return 'Attestation signer does not match the requested signer';
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
    case 'binding.nonce_mismatch':
      return 'Attestation nonce does not match';
    case 'binding.report_data_invalid':
      return 'Attestation report data is invalid';
    case 'binding.report_data_mismatch':
      return 'Attestation report data does not match the verified quote';
    case 'binding.spki_fingerprint_missing':
      return 'Attestation is missing its SPKI fingerprint';
    case 'binding.spki_fingerprint_mismatch':
      return 'Attestation SPKI fingerprint does not match the peer connection';
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
      return 'GPU evidence was rejected';
    case 'provenance.verification_failed':
      return 'Deployment provenance verification failed';
    case 'signature.unavailable':
      return 'Completion signature is unavailable';
    case 'signature.kind_mismatch':
      return 'Completion signature does not support this verification claim';
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
