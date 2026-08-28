import type { TcbStatus } from '../types/verification';

type ApiResource =
  | 'model_attestation'
  | 'gateway_attestation'
  | 'completion_signature';

/** A JSON-safe description of a Cloud API failure.
 *
 * `code` and any fields in `details` are the public error contract.
 * `message` is only for people; consumers must not parse it. The shape is kept
 * deliberately free of API keys, nonces, quotes, prompts, and response bytes.
 * Future language SDKs should preserve these codes and detail field names.
 */
export type ApiFailure =
  | {
      code: 'api.transport_failed';
      details: {
        resource: ApiResource;
        reason: 'request' | 'response_body';
      };
      retryable: true;
    }
  | {
      code: 'api.http_status';
      details: {
        resource: ApiResource;
        status: number;
      };
      retryable: boolean;
    }
  | {
      code: 'api.invalid_json';
      details: { resource: ApiResource };
    }
  | {
      code: 'api.invalid_response';
      details: {
        path: string;
        expected: string;
        actual: string;
      };
    }
  | {
      code: 'api.nonce_mismatch';
      details: {
        resource: 'model_attestation' | 'gateway_attestation';
      };
    }
  | {
      code: 'api.unexpected_model_attestation_count';
      details: { actualCount: number };
    }
  | {
      code: 'api.ambiguous_model_attestation_signer';
      details: { matchingCount: number; totalCount: number };
    }
  | {
      code: 'api.model_attestation_signer_not_found';
    }
  | {
      code: 'api.completion_signature_unavailable';
      details: { providerErrorCode: string };
    };

/** A JSON-safe description of a local verification failure.
 *
 * `code` and any fields in `details` are the public error contract.
 * `message` is only for people; consumers must not parse it. The shape is kept
 * deliberately free of API keys, nonces, quotes, prompts, and response bytes.
 * Future language SDKs should preserve these codes and detail field names.
 */
export type VerificationFailure =
  | {
      code: 'input.invalid';
      details: {
        field: string;
        reason: 'invalid_hex' | 'wrong_length' | 'invalid_jwt';
        expected?: string;
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      code: 'quote.collateral_unavailable';
      retryable: true;
    }
  | {
      code: 'quote.verification_failed';
      details: {
        reason: 'invalid_encoding' | 'invalid_quote' | 'verifier_error';
      };
    }
  | {
      code: 'quote.invalid_result';
      details: {
        path: string;
        expected: string;
        actual: string;
      };
    }
  | {
      code: 'quote.unsupported_report_type';
      details: { expected: 'TD10' };
    }
  | {
      code: 'policy.debug_enabled';
    }
  | {
      code: 'policy.tcb_status_not_allowed';
      details: {
        actual: TcbStatus;
        accepted: readonly TcbStatus[];
        advisoryIds: readonly string[];
      };
    }
  | {
      code: 'policy.gpu_evidence_required';
    }
  | {
      code: 'policy.peer_tls_binding_required';
    }
  | {
      code: 'binding.nonce_mismatch';
      details: {
        source: 'attestationNonce' | 'quoteReportData' | 'nvidiaPayload';
      };
    }
  | {
      code: 'binding.report_data_invalid';
      details: {
        source: 'quoteReportData' | 'reportedQuoteData';
        reason: 'invalid_hex' | 'wrong_length';
        expectedBytes: 64;
        actualBytes?: number;
      };
    }
  | {
      code: 'binding.report_data_mismatch';
      details: {
        source: 'reportedQuoteData' | 'signerBinding' | 'signerTlsBinding';
      };
    }
  | {
      code: 'binding.spki_fingerprint_missing';
    }
  | {
      code: 'binding.spki_fingerprint_mismatch';
    }
  | {
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
      code: 'measurement.rtmr3_mismatch';
      details: {
        reason: 'wrong_length' | 'no_events' | 'replay_mismatch';
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      code: 'measurement.mrconfigid_invalid';
      details: {
        reason: 'wrong_length' | 'unsupported_version';
        minimumBytes?: number;
        actualBytes?: number;
        version?: number;
      };
    }
  | {
      code: 'measurement.app_compose_mrconfigid_mismatch';
    }
  | {
      code: 'gpu.payload_invalid';
      details: { reason: 'invalid_json' | 'nonce_missing' };
    }
  | {
      code: 'gpu.nras_request_failed';
      details: {
        reason: 'timeout' | 'transport' | 'http_status';
        status?: number;
      };
      retryable: boolean;
    }
  | {
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
      code: 'gpu.attestation_rejected';
      details: { source: 'nras' | 'custom_verifier' };
    }
  | {
      code: 'provenance.verification_failed';
    }
  | {
      code: 'signature.kind_mismatch';
      details: {
        expected: 'provider_tee' | 'gateway';
        actual: 'provider_tee' | 'gateway';
      };
    }
  | {
      code: 'signature.payload_mismatch';
      details: {
        source: 'request_model' | 'signed_payload';
        reason: 'invalid_json' | 'missing_model' | 'text_mismatch';
      };
    }
  | {
      code: 'signature.format_invalid';
      details: {
        field: 'signature' | 'signer.signingAddress';
        reason: 'invalid_hex' | 'wrong_length';
        expectedBytes?: number;
        actualBytes?: number;
      };
    }
  | {
      code: 'signature.invalid';
      details: { signingAlgo: 'ecdsa' | 'ed25519' };
    }
  | {
      code: 'signature.signer_mismatch';
    };

type SdkFailure = ApiFailure | VerificationFailure;
type SerializedFailure<TFailure extends SdkFailure> = TFailure extends unknown
  ? Omit<TFailure, 'retryable'>
  : never;
type SdkErrorJson<TFailure extends SdkFailure> = {
  name: string;
  message: string;
  failure: SerializedFailure<TFailure>;
  retryable: boolean;
};

export type ApiErrorCode = ApiFailure['code'];
export type VerificationErrorCode = VerificationFailure['code'];
export type ApiErrorJson = SdkErrorJson<ApiFailure>;
export type VerificationErrorJson = SdkErrorJson<VerificationFailure>;

export type SdkErrorOptions = { cause?: unknown };
type InputFailure = Extract<VerificationFailure, { code: 'input.invalid' }>;
type InputErrorParams = {
  field: string;
  reason: InputFailure['details']['reason'];
  details?: Omit<InputFailure['details'], 'field' | 'reason'>;
};

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

  get retryable(): boolean {
    return isRetryableFailure(this.failure);
  }

  /** Safe structured data for logs and cross-process diagnostics. */
  toJSON(): VerificationErrorJson {
    return {
      name: this.name,
      message: this.message,
      failure: serializeFailure(this.failure),
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

  get retryable(): boolean {
    return isRetryableFailure(this.failure);
  }

  /** Safe structured data for logs and cross-process diagnostics. */
  toJSON(): ApiErrorJson {
    return {
      name: this.name,
      message: this.message,
      failure: serializeFailure(this.failure),
      retryable: this.retryable,
    };
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

export function inputError({
  field,
  reason,
  details = {},
}: InputErrorParams): VerificationError {
  return new VerificationError({
    code: 'input.invalid',
    details: { field, reason, ...details },
  });
}

function isRetryableFailure(failure: SdkFailure): boolean {
  return 'retryable' in failure && failure.retryable;
}

function serializeFailure<TFailure extends SdkFailure>(
  failure: TFailure,
): SerializedFailure<TFailure> {
  if (!('retryable' in failure)) {
    return failure as SerializedFailure<TFailure>;
  }
  const { retryable: _retryable, ...serialized } = failure;
  return serialized as SerializedFailure<TFailure>;
}

function formatFailureMessage(failure: SdkFailure): string {
  switch (failure.code) {
    case 'input.invalid':
      return `[${failure.code}] ${formatInputFailure(failure.details)}`;
    case 'api.transport_failed':
      return `[${failure.code}] Cloud API ${formatApiResource(failure.details.resource)} ${
        failure.details.reason === 'request'
          ? 'request failed'
          : 'response body could not be read'
      }`;
    case 'api.http_status':
      return `[${failure.code}] Cloud API ${formatApiResource(failure.details.resource)} returned HTTP ${failure.details.status}`;
    case 'api.invalid_json':
      return `[${failure.code}] Cloud API ${formatApiResource(failure.details.resource)} returned invalid JSON`;
    case 'api.invalid_response':
      return `[${failure.code}] Cloud API response has an invalid ${failure.details.path}: expected ${failure.details.expected}, received ${failure.details.actual}`;
    case 'api.nonce_mismatch':
      return `[${failure.code}] Cloud API ${formatApiResource(failure.details.resource)} nonce does not match the request`;
    case 'api.unexpected_model_attestation_count':
      return `[${failure.code}] Cloud API returned ${failure.details.actualCount} model attestations; expected exactly one`;
    case 'api.ambiguous_model_attestation_signer':
      return `[${failure.code}] Cloud API returned ${failure.details.matchingCount} model attestations for the requested signer (${failure.details.totalCount} total)`;
    case 'api.model_attestation_signer_not_found':
      return `[${failure.code}] Cloud API returned no model attestation for the requested signer`;
    case 'api.completion_signature_unavailable':
      return `[${failure.code}] Cloud API did not provide a completion signature (${failure.details.providerErrorCode})`;
    case 'quote.collateral_unavailable':
      return `[${failure.code}] Intel quote collateral is unavailable`;
    case 'quote.verification_failed':
      return `[${failure.code}] Intel TDX quote verification failed: ${failure.details.reason}`;
    case 'quote.invalid_result':
      return `[${failure.code}] Quote verifier returned an invalid ${failure.details.path}: expected ${failure.details.expected}, received ${failure.details.actual}`;
    case 'quote.unsupported_report_type':
      return `[${failure.code}] Verified quote has an unsupported report type; expected ${failure.details.expected}`;
    case 'policy.debug_enabled':
      return `[${failure.code}] TDX debug mode is enabled`;
    case 'policy.tcb_status_not_allowed':
      return `[${failure.code}] TDX TCB status ${failure.details.actual} is not allowed by policy`;
    case 'policy.gpu_evidence_required':
      return `[${failure.code}] GPU evidence is required by policy`;
    case 'policy.peer_tls_binding_required':
      return `[${failure.code}] A client-observed Gateway TLS peer is required by policy`;
    case 'binding.nonce_mismatch':
      return `[${failure.code}] Nonce in ${failure.details.source} does not match`;
    case 'binding.report_data_invalid':
      return `[${failure.code}] ${failure.details.source} is invalid: ${failure.details.reason}`;
    case 'binding.report_data_mismatch':
      return `[${failure.code}] ${failure.details.source} does not match the verified quote`;
    case 'binding.spki_fingerprint_missing':
      return `[${failure.code}] Attestation is missing its SPKI fingerprint`;
    case 'binding.spki_fingerprint_mismatch':
      return `[${failure.code}] Attestation SPKI fingerprint does not match the observed TLS peer`;
    case 'measurement.event_log_invalid':
      return `[${failure.code}] Attestation event log is invalid at ${failure.details.path}: ${failure.details.reason}`;
    case 'measurement.rtmr3_mismatch':
      return `[${failure.code}] Attestation event log does not match RTMR3: ${failure.details.reason}`;
    case 'measurement.mrconfigid_invalid':
      return `[${failure.code}] Quote MRCONFIGID is invalid: ${failure.details.reason}`;
    case 'measurement.app_compose_mrconfigid_mismatch':
      return `[${failure.code}] App compose does not match quote MRCONFIGID`;
    case 'gpu.payload_invalid':
      return `[${failure.code}] GPU evidence payload is invalid: ${failure.details.reason}`;
    case 'gpu.nras_request_failed':
      return `[${failure.code}] NVIDIA NRAS request failed: ${failure.details.reason}`;
    case 'gpu.nras_response_invalid':
      return `[${failure.code}] NVIDIA NRAS response is invalid: ${failure.details.reason}`;
    case 'gpu.attestation_rejected':
      return `[${failure.code}] GPU evidence was rejected by ${failure.details.source}`;
    case 'provenance.verification_failed':
      return `[${failure.code}] Deployment provenance verification failed`;
    case 'signature.kind_mismatch':
      return `[${failure.code}] Expected a ${failure.details.expected} signature, received ${failure.details.actual}`;
    case 'signature.payload_mismatch':
      return `[${failure.code}] Completion signature does not match the ${failure.details.source}: ${failure.details.reason}`;
    case 'signature.format_invalid':
      return `[${failure.code}] Completion ${failure.details.field} is invalid: ${failure.details.reason}`;
    case 'signature.invalid':
      return `[${failure.code}] Completion signature is invalid for ${failure.details.signingAlgo}`;
    case 'signature.signer_mismatch':
      return `[${failure.code}] Completion signature signer does not match the attestation`;
  }
}

function formatApiResource(resource: ApiResource): string {
  switch (resource) {
    case 'model_attestation':
      return 'model attestation';
    case 'gateway_attestation':
      return 'Gateway attestation';
    case 'completion_signature':
      return 'completion signature';
  }
}

function formatInputFailure(
  details: Extract<VerificationFailure, { code: 'input.invalid' }>['details'],
): string {
  const subject = details.field;
  switch (details.reason) {
    case 'invalid_hex':
      return `${subject} must be hexadecimal`;
    case 'wrong_length':
      if (details.expected !== undefined) {
        return `${subject} must be ${details.expected}`;
      }
      return details.expectedBytes === undefined ||
        details.actualBytes === undefined
        ? `${subject} has the wrong length`
        : `${subject} must be ${details.expectedBytes} bytes; received ${details.actualBytes}`;
    case 'invalid_jwt':
      return `${subject} must be a valid JWT`;
  }
}
