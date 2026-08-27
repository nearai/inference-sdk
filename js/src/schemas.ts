import * as v from 'valibot';
import type { Awaitable } from './types/shared';

/** Values accepted by external NEAR AI and quote-verifier responses. */
const SigningAlgorithmValues = ['ecdsa', 'ed25519'] as const;
const CompletionSignatureKindValues = ['provider_tee', 'gateway'] as const;
const CompletionSignatureResponseFields = [
  'text',
  'signature',
  'signing_address',
  'signing_algo',
  'signature_kind',
] as const;
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
  // The event log is opaque JSON at the wire boundary. Its event-specific
  // structure is validated while replaying measurements.
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
  // Decode this separately so a malformed nested value reports the stable
  // public `…info` path rather than an implementation-specific envelope path.
  info: v.optional(v.unknown()),
});

const CloudApiAttestationEntries = {
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
  // Each item is decoded separately to retain its `model_attestations[index]`
  // error path and validate the nested `info` envelope once.
  model_attestations: v.array(v.unknown()),
});

export const CloudApiGatewayAttestationResponseSchema = objectSchema({
  // Decode the nested report separately to retain the public
  // `gateway_attestation` error path.
  gateway_attestation: v.unknown(),
});

export const CloudApiUnavailableSignatureResponseSchema = v.pipe(
  objectSchema({
    error_code: v.string(),
    message: v.string(),
  }),
  // An error envelope must not hide a malformed signature response just
  // because it also contains error metadata. The success parser will then
  // produce the relevant `api.invalid_response` error instead.
  v.check(
    (value) =>
      !CompletionSignatureResponseFields.some((field) =>
        Object.hasOwn(value, field),
      ),
  ),
);

export const CloudApiCompletionSignatureResponseSchema = objectSchema({
  text: v.string(),
  signature: v.string(),
  signing_address: v.string(),
  signing_algo: SigningAlgorithmSchema,
  signature_kind: v.picklist(CompletionSignatureKindValues),
});
