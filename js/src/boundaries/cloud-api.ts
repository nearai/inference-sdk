import { Buffer } from 'buffer';
import * as v from 'valibot';
import {
  CloudApiCompletionSignatureResultSchema,
  CloudApiGatewayAttestationResponseSchema,
  CloudApiModelAttestationResponseSchema,
} from '../schemas';
import type { GatewayAttestation } from '../types/attestation-gateway';
import type { ChutesModelAttestation } from '../types/attestation-chutes';
import type {
  ModelAttestation,
  NearModelAttestation,
} from '../types/attestation-model';
import type {
  AttestationEvidence,
  SigningAlgo,
} from '../types/attestation-common';
import type {
  CloudApiGatewayAttestation,
  CloudApiNearModelAttestation,
  CloudApiChutesModelAttestation,
  CloudApiCompletionSignatureResult,
} from '../types/cloud-api';
import type { CompletionSignature } from '../types/chat';
import type {
  OhttpAttestation,
  OhttpAttestationResponse,
} from '../types/ohttp';
import { trimHexPrefix } from '../utils/common';
import { ApiError } from '../utils/errors';

type CloudApiAttestation =
  | CloudApiGatewayAttestation
  | CloudApiNearModelAttestation;

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
  return parsed.output.model_attestations.map((attestation, index) => {
    const label = `model_attestations[${index}]`;
    return attestation.provider === 'chutes'
      ? mapChutesModelAttestation(attestation, label)
      : mapModelAttestation(attestation, label);
  });
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
  return {
    ...mapGatewayAttestation(
      parsed.output.gateway_attestation,
      'gateway_attestation',
    ),
    ...(parsed.output.ohttp_attestation === undefined
      ? {}
      : {
          ohttpAttestation: mapOhttpAttestation(
            parsed.output.ohttp_attestation,
          ),
        }),
  };
}

/** Map report-level OHTTP metadata shared by Gateway and direct endpoints. */
export function mapOhttpAttestation(
  attestation: OhttpAttestationResponse,
): OhttpAttestation {
  return {
    signingAlgo: attestation.signing_algo,
    signingKey: validateWireHex({
      value: attestation.signing_key,
      label: 'ohttp_attestation.signing_key',
      expected: '32-byte hexadecimal Ed25519 public key',
      expectedBytes: 32,
    }),
    keyConfig: validateWireHex({
      value: attestation.key_config,
      label: 'ohttp_attestation.key_config',
      expected: 'non-empty hexadecimal OHTTP key configuration',
    }),
    signature: validateWireHex({
      value: attestation.signature,
      label: 'ohttp_attestation.signature',
      expected: '64-byte hexadecimal Ed25519 signature',
      expectedBytes: 64,
    }),
  };
}

/** Decode a Cloud API completion signature or report an unavailable signature. */
export function decodeCompletionSignature(value: unknown): CompletionSignature {
  const parsed = v.safeParse(CloudApiCompletionSignatureResultSchema, value);
  if (!parsed.success) {
    throw invalidCloudApiResponse({
      issue: parsed.issues[0],
      fallbackPath: 'signature',
    });
  }
  return mapCompletionSignature(parsed.output);
}

/** Map a decoded wire signature without parsing an HTTP response a second time. */
export function mapCompletionSignature(
  response: CloudApiCompletionSignatureResult,
): CompletionSignature {
  if ('error_code' in response) {
    throw new ApiError({
      code: 'api.completion_signature_unavailable',
      details: {
        providerErrorCode: response.error_code,
        providerMessage: response.message,
      },
    });
  }
  return {
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
  };
}

export function mapModelAttestation(
  attestation: CloudApiNearModelAttestation,
  label: string,
): NearModelAttestation {
  const evidence = mapAttestationEvidence({ attestation, label });
  return {
    provider: 'near',
    ...evidence,
    ...(attestation.signing_public_key === undefined
      ? {}
      : {
          signingPublicKey: validateWireHex({
            value: attestation.signing_public_key,
            label: `${label}.signing_public_key`,
            expected: 'non-empty hexadecimal model public key',
          }),
        }),
    ...(attestation.report_data === undefined
      ? {}
      : { reportedQuoteData: attestation.report_data }),
    ...(attestation.nvidia_payload === undefined
      ? {}
      : { nvidiaPayload: attestation.nvidia_payload }),
  };
}

function mapChutesModelAttestation(
  attestation: CloudApiChutesModelAttestation,
  label: string,
): ChutesModelAttestation {
  // Chutes hashes the textual nonce and key into report_data. Validate their
  // wire encodings without changing case, padding, or the original strings.
  if (!/^[0-9a-fA-F]{64}$/.test(attestation.nonce)) {
    throw invalidCloudApiResponse({
      path: `${label}.nonce`,
      expected: '32-byte hexadecimal nonce without a prefix',
      value: attestation.nonce,
    });
  }
  const quote = validateWireBase64({
    value: attestation.quote_b64,
    label: `${label}.quote_b64`,
    trim: true,
  });
  validateWireBase64({
    value: attestation.certificate_b64,
    label: `${label}.certificate_b64`,
    trim: true,
  });
  validateWireBase64({
    value: attestation.e2e_pubkey,
    label: `${label}.e2e_pubkey`,
    expectedBytes: 1184,
  });
  const gpuEvidence = attestation.gpu_evidence.map((gpu, index) => {
    for (const field of ['certificate', 'evidence'] as const) {
      validateWireBase64({
        value: gpu[field],
        label: `${label}.gpu_evidence[${index}].${field}`,
        trim: true,
      });
    }
    return { ...gpu };
  });
  return {
    provider: 'chutes',
    nonce: attestation.nonce,
    intelQuote: quote.toString('hex'),
    certificate: attestation.certificate_b64,
    publicKey: attestation.e2e_pubkey,
    gpuEvidence,
    ...(attestation.instance_id === undefined
      ? {}
      : { instanceId: attestation.instance_id }),
  };
}

type ValidateWireBase64Params = {
  value: string;
  label: string;
  expectedBytes?: number;
  trim?: boolean;
};

function validateWireBase64({
  value,
  label,
  expectedBytes,
  trim = false,
}: ValidateWireBase64Params): Buffer {
  const encoded = trim ? value.trim() : value;
  const bytes = Buffer.from(encoded, 'base64');
  if (
    encoded.length === 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      encoded,
    ) ||
    bytes.toString('base64') !== encoded ||
    (expectedBytes !== undefined && bytes.length !== expectedBytes)
  ) {
    throw invalidCloudApiResponse({
      path: label,
      expected:
        expectedBytes === undefined
          ? 'non-empty standard base64'
          : `standard base64 encoding of ${expectedBytes} bytes`,
      value,
    });
  }
  return bytes;
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

type ValidateWireHexParams = {
  value: string;
  label: string;
  expected: string;
  expectedBytes?: number;
};

function validateWireHex({
  value,
  label,
  expected,
  expectedBytes,
}: ValidateWireHexParams): string {
  const normalized = trimHexPrefix(value);
  const hasExpectedLength =
    expectedBytes === undefined || normalized.length === expectedBytes * 2;
  if (
    normalized.length === 0 ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(normalized) ||
    !hasExpectedLength
  ) {
    throw invalidCloudApiResponse({ path: label, expected, value });
  }
  return value;
}

export function invalidCloudApiResponse({
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
