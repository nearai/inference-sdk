import * as v from 'valibot';
import type { Awaitable } from './types/shared';

/** Values accepted by external NEAR AI and quote-verifier responses. */
const SigningAlgorithmValues = ['ecdsa', 'ed25519'] as const;
const TcbStatusValues = [
  'UpToDate',
  'SWHardeningNeeded',
  'ConfigurationNeeded',
  'ConfigurationAndSWHardeningNeeded',
  'OutOfDate',
  'OutOfDateConfigurationNeeded',
  'Revoked',
  'Unknown',
] as const;

export const SigningAlgorithmSchema = v.picklist(SigningAlgorithmValues);

export const TcbStatusSchema = v.picklist(TcbStatusValues);

function isFunction(value: unknown): boolean {
  return typeof value === 'function';
}

function isUint8Array(value: unknown): boolean {
  return value instanceof Uint8Array;
}

function isPlainObject(value: unknown): value is object {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isNonArrayObject(value: unknown): value is object {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const Uint8ArraySchema = v.custom<Uint8Array>(isUint8Array);
const PlainObjectSchema = v.custom<object>(isPlainObject);
const NonArrayObjectSchema = v.custom<object>(isNonArrayObject);

function objectSchema<TEntries extends v.ObjectEntries>(entries: TEntries) {
  return v.intersect([v.object(entries), PlainObjectSchema] as const);
}

// ---------------------------------------------------------------------------
// External quote-verifier and Cloud API response shapes
// ---------------------------------------------------------------------------

export const AttestationEventLogSchema = v.union([
  v.string(),
  v.pipe(v.array(v.unknown()), v.readonly()),
]);

export const QuoteVerificationResultSchema = objectSchema({
  tcbStatus: TcbStatusSchema,
  advisoryIds: v.pipe(v.array(v.string()), v.readonly()),
  debugEnabled: v.boolean(),
  reportData: Uint8ArraySchema,
  mrConfigId: Uint8ArraySchema,
  rtMr3: Uint8ArraySchema,
});

/** Minimal response surface the client consumes from an injected transport. */
export const ResponseLikeSchema = v.pipe(
  NonArrayObjectSchema,
  v.object({
    ok: v.boolean(),
    status: v.number(),
    text: v.custom<() => Awaitable<string>>(isFunction),
  }),
);

export const ResponseBodySchema = v.string();

export const CloudApiTcbInfoSchema = objectSchema({
  app_compose: v.string(),
});

export const CloudApiInfoSchema = objectSchema({
  tcb_info: v.union([v.string(), CloudApiTcbInfoSchema]),
});

export const CloudApiAttestationInfoEnvelopeSchema = objectSchema({
  info: v.optional(v.unknown()),
});

const CloudApiAttestationEntries = {
  // Parse this nested object separately so error paths remain tied to the
  // public Cloud API field rather than an implementation-specific envelope.
  info: v.optional(v.unknown()),
  request_nonce: v.string(),
  signing_algo: SigningAlgorithmSchema,
  signing_address: v.string(),
  intel_quote: v.string(),
  event_log: AttestationEventLogSchema,
  tls_cert_fingerprint: v.optional(v.nullable(v.string())),
  report_data: v.optional(v.string()),
};

export const CloudApiModelAttestationSchema = objectSchema({
  ...CloudApiAttestationEntries,
  nvidia_payload: v.optional(v.nullable(v.string())),
});

export const CloudApiGatewayAttestationSchema = objectSchema({
  ...CloudApiAttestationEntries,
  report_data: v.string(),
});

export const CloudApiModelAttestationResponseSchema = objectSchema({
  model_attestations: v.array(v.unknown()),
});

export const CloudApiGatewayAttestationResponseSchema = objectSchema({
  gateway_attestation: v.unknown(),
});

export const CloudApiUnavailableSignatureResponseSchema = objectSchema({
  error_code: v.string(),
  message: v.string(),
});

export const CloudApiCompletionSignatureResponseSchema = objectSchema({
  text: v.string(),
  signature: v.string(),
  signing_address: v.string(),
  signing_algo: SigningAlgorithmSchema,
  // A strict parser below preserves the API's dedicated signature-kind error
  // contract instead of collapsing it into a generic wire-schema error.
  signature_kind: v.optional(v.unknown()),
});
