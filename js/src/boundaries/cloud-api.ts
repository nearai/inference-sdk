import * as v from 'valibot';
import {
  CloudApiCompletionSignatureLookupSchema,
  CloudApiGatewayAttestationResponseSchema,
  CloudApiModelAttestationResponseSchema,
} from '../schemas';
import type { GatewayAttestation } from '../types/attestation-gateway';
import type { ModelAttestation } from '../types/attestation-model';
import type {
  AttestationEvidence,
  SigningAlgo,
} from '../types/attestation-common';
import type {
  CloudApiGatewayAttestation,
  CloudApiModelAttestation,
} from '../types/cloud-api';
import type {
  CompletionSignatureLookup,
  SignatureUnavailable,
} from '../types/chat';
import { trimHexPrefix } from '../utils/common';
import { ApiError } from '../utils/errors';

type CloudApiAttestation =
  | CloudApiGatewayAttestation
  | CloudApiModelAttestation;

type MapAttestationEvidenceParams = {
  attestation: CloudApiAttestation;
  label: string;
};

type ValidateWireSigningAddressParams = {
  signingAddress: string;
  signingAlgo: SigningAlgo;
  label: string;
};

type InvalidCloudApiResponseParams =
  | {
      issue: v.BaseIssue<unknown>;
      fallbackPath: string;
    }
  | {
      path: string;
      expected: string;
      value: unknown;
    };

/**
 * Cloud API's HTTP response boundary.
 *
 * Each endpoint is decoded once from JSON wire data into its public SDK value.
 * The request helper owns transport and JSON errors; this module owns wire
 * shape, JSON-in-JSON `tcb_info`, and the snake_case-to-domain mapping.
 */
export function decodeModelAttestationReport(
  value: unknown,
): readonly ModelAttestation[] {
  const parsed = v.safeParse(CloudApiModelAttestationResponseSchema, value);
  if (!parsed.success) {
    throw invalidCloudApiResponse({
      issue: parsed.issues[0],
      fallbackPath: 'model attestation report',
    });
  }
  return parsed.output.model_attestations.map((attestation, index) =>
    mapModelAttestation(attestation, `model_attestations[${index}]`),
  );
}

/** Decode a Gateway attestation report from Cloud API JSON. */
export function decodeGatewayAttestationReport(
  value: unknown,
): GatewayAttestation {
  const parsed = v.safeParse(CloudApiGatewayAttestationResponseSchema, value);
  if (!parsed.success) {
    throw invalidCloudApiResponse({
      issue: parsed.issues[0],
      fallbackPath: 'gateway attestation report',
    });
  }
  return mapGatewayAttestation(
    parsed.output.gateway_attestation,
    'gateway_attestation',
  );
}

/** Decode Cloud API's found-or-unavailable completion-signature response. */
export function decodeCompletionSignatureLookup(
  value: unknown,
): CompletionSignatureLookup {
  const parsed = v.safeParse(CloudApiCompletionSignatureLookupSchema, value);
  if (!parsed.success) {
    throw invalidCloudApiResponse({
      issue: parsed.issues[0],
      fallbackPath: 'signature',
    });
  }
  const response = parsed.output;
  if ('error_code' in response) {
    const unavailable: SignatureUnavailable = {
      errorCode: response.error_code,
      message: response.message,
    };
    return { status: 'unavailable', unavailable };
  }
  return {
    status: 'found',
    signature: {
      kind: response.signature_kind,
      signedText: response.text,
      signature: response.signature,
      signer: {
        signingAlgo: response.signing_algo,
        signingAddress: validateWireSigningAddress({
          signingAddress: response.signing_address,
          signingAlgo: response.signing_algo,
          label: 'signature.signing_address',
        }),
      },
    },
  };
}

function mapModelAttestation(
  attestation: CloudApiModelAttestation,
  label: string,
): ModelAttestation {
  const evidence = mapAttestationEvidence({ attestation, label });
  return {
    ...evidence,
    ...(attestation.report_data === undefined
      ? {}
      : { reportedQuoteData: attestation.report_data }),
    ...(attestation.nvidia_payload === undefined
      ? {}
      : { nvidiaPayload: attestation.nvidia_payload }),
  };
}

function mapGatewayAttestation(
  attestation: CloudApiGatewayAttestation,
  label: string,
): GatewayAttestation {
  return {
    ...mapAttestationEvidence({ attestation, label }),
    reportedQuoteData: attestation.report_data,
    ...(attestation.tls_cert_fingerprint === undefined
      ? {}
      : { spkiFingerprint: attestation.tls_cert_fingerprint }),
  };
}

function mapAttestationEvidence({
  attestation,
  label,
}: MapAttestationEvidenceParams): AttestationEvidence {
  const signingAlgo = attestation.signing_algo;
  const signingAddress = validateWireSigningAddress({
    signingAddress: attestation.signing_address,
    signingAlgo,
    label: `${label}.signing_address`,
  });
  return {
    nonce: validateWireNonce(
      attestation.request_nonce,
      `${label}.request_nonce`,
    ),
    signer: { signingAlgo, signingAddress },
    intelQuote: attestation.intel_quote,
    eventLog: attestation.event_log,
    appCompose: attestation.info.tcb_info.app_compose,
  };
}

function validateWireNonce(value: string, label: string): string {
  const normalized = trimHexPrefix(value);
  if (normalized.length !== 64 || !/^[0-9a-fA-F]+$/.test(normalized)) {
    throw invalidCloudApiResponse({
      path: label,
      expected: '32-byte hexadecimal nonce',
      value,
    });
  }
  return value;
}

function validateWireSigningAddress({
  signingAddress,
  signingAlgo,
  label,
}: ValidateWireSigningAddressParams): string {
  const normalized = trimHexPrefix(signingAddress);
  const expectedBytes = signingAlgo === 'ecdsa' ? 20 : 32;
  if (
    normalized.length !== expectedBytes * 2 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw invalidCloudApiResponse({
      path: label,
      expected: `${expectedBytes}-byte hexadecimal signing address`,
      value: signingAddress,
    });
  }
  return signingAddress;
}

function invalidCloudApiResponse({
  ...params
}: InvalidCloudApiResponseParams): ApiError {
  const details =
    'issue' in params
      ? {
          path: issuePath(params.issue, params.fallbackPath),
          expected: describeExpected(params.issue.expected),
          actual: describeValue(params.issue.input),
        }
      : {
          path: params.path,
          expected: params.expected,
          actual: describeValue(params.value),
        };
  return new ApiError({
    code: 'api.invalid_response',
    details,
  });
}

function issuePath(issue: v.BaseIssue<unknown>, fallbackPath: string): string {
  const path = v.getDotPath(issue);
  if (!path) {
    return fallbackPath;
  }
  return path
    .split('.')
    .reduce(
      (formatted, segment) =>
        /^[0-9]+$/.test(segment)
          ? `${formatted}[${segment}]`
          : formatted.length === 0
            ? segment
            : `${formatted}.${segment}`,
      '',
    );
}

function describeExpected(expected: string | null): string {
  switch (expected) {
    case null:
      return 'valid input';
    case 'Object':
      return 'object';
    case 'Array':
      return 'array';
    case 'string':
      return 'string';
    case 'boolean':
      return 'boolean';
    default:
      return expected;
  }
}

function describeValue(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}
