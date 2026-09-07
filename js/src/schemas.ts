import * as v from 'valibot';

/** Values accepted at external HTTP, adapter, and signed-byte boundaries. */
const SigningAlgoValues = ['ecdsa', 'ed25519'] as const;
const CompletionSignatureKindValues = ['provider_tee', 'gateway'] as const;
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

export const SigningAlgoSchema = v.picklist(SigningAlgoValues);

export const TcbStatusSchema = v.picklist(TcbStatusValues);

function isUint8Array(value: unknown): boolean {
  return value instanceof Uint8Array;
}

function isNonArrayObject(value: unknown): value is object {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const Uint8ArraySchema = v.custom<Uint8Array>(isUint8Array);
const NonArrayObjectSchema = v.custom<object>(isNonArrayObject);

function objectSchema<TEntries extends v.ObjectEntries>(entries: TEntries) {
  return v.pipe(NonArrayObjectSchema, v.object(entries));
}

function looseObjectSchema<TEntries extends v.ObjectEntries>(
  entries: TEntries,
) {
  return v.pipe(NonArrayObjectSchema, v.looseObject(entries));
}

// ---------------------------------------------------------------------------
// External quote-verifier, Cloud API, and NRAS response shapes
// ---------------------------------------------------------------------------

export const AttestationEventLogSchema = v.union([
  v.string(),
  // The event log is opaque JSON at the wire boundary. Its event-specific
  // structure is validated while replaying measurements.
  v.pipe(v.array(v.unknown()), v.readonly()),
]);

const U32Schema = v.pipe(
  v.number(),
  v.integer(),
  v.minValue(0),
  v.maxValue(0xffffffff),
);

export const DstackEventLogEntrySchema = looseObjectSchema({
  digest: v.string(),
  imr: U32Schema,
  event_type: v.optional(U32Schema, 0),
  event: v.optional(v.string(), ''),
  event_payload: v.optional(v.string(), ''),
});

export const DstackEventLogSchema = v.array(DstackEventLogEntrySchema);

export const SerializedDstackEventLogSchema = v.pipe(
  v.string(),
  v.parseJson(),
  DstackEventLogSchema,
);

export const NvidiaPayloadNonceSchema = looseObjectSchema({
  nonce: v.string(),
});

export const CompletionRequestModelSchema = looseObjectSchema({
  model: v.pipe(v.string(), v.minLength(1)),
});

export const QuoteVerificationResultSchema = objectSchema({
  tcbStatus: TcbStatusSchema,
  advisoryIds: v.pipe(v.array(v.string()), v.readonly()),
  debugEnabled: v.boolean(),
  reportData: Uint8ArraySchema,
  mrConfigId: Uint8ArraySchema,
  rtMr3: Uint8ArraySchema,
});

export const CloudApiTcbInfoSchema = objectSchema({
  app_compose: v.string(),
});

const CloudApiTcbInfoJsonSchema = v.pipe(
  v.string(),
  v.parseJson(),
  CloudApiTcbInfoSchema,
);

export const CloudApiInfoSchema = objectSchema({
  // Cloud API has returned this field both as an object and as a JSON string.
  // Decode either wire form into the same object before domain mapping.
  tcb_info: v.union([CloudApiTcbInfoSchema, CloudApiTcbInfoJsonSchema]),
});

// Cloud API may encode optional evidence as either a missing field or JSON
// null. Canonicalize both at the HTTP boundary so public SDK values only use
// the ordinary JavaScript absence state.
const OptionalCloudApiStringSchema = v.pipe(
  v.optional(v.nullable(v.string())),
  v.transform((value) => value ?? undefined),
);

const CloudApiAttestationEntries = {
  request_nonce: v.string(),
  signing_algo: SigningAlgoSchema,
  signing_address: v.string(),
  intel_quote: v.string(),
  event_log: AttestationEventLogSchema,
  info: CloudApiInfoSchema,
  tls_cert_fingerprint: OptionalCloudApiStringSchema,
  report_data: OptionalCloudApiStringSchema,
};

export const CloudApiModelAttestationSchema = objectSchema({
  ...CloudApiAttestationEntries,
  nvidia_payload: OptionalCloudApiStringSchema,
});

export const CloudApiGatewayAttestationSchema = objectSchema({
  ...CloudApiAttestationEntries,
  report_data: v.string(),
});

export const CloudApiModelAttestationResponseSchema = objectSchema({
  // Cloud API omits this field when no model provider produced evidence.
  // Normalize that wire form before the fetch helper reports the expected
  // candidate-count error.
  model_attestations: v.optional(v.array(CloudApiModelAttestationSchema), []),
});

export const CloudApiGatewayAttestationResponseSchema = objectSchema({
  gateway_attestation: CloudApiGatewayAttestationSchema,
});

const CompletionSignatureFieldNames = [
  'text',
  'signature',
  'signing_address',
  'signing_algo',
  'signature_kind',
] as const;

export const CloudApiUnavailableSignatureResponseSchema = v.pipe(
  looseObjectSchema({
    error_code: v.string(),
    message: v.string(),
  }),
  // Do not classify a response that contains completion-signature fields as
  // unavailable. The signature schema gets first chance to decode it.
  v.check((value) => {
    const record = value as Record<string, unknown>;
    return CompletionSignatureFieldNames.every(
      (field) => record[field] === undefined,
    );
  }),
);

export const CloudApiCompletionSignatureResponseSchema = objectSchema({
  text: v.string(),
  signature: v.string(),
  signing_address: v.string(),
  signing_algo: SigningAlgoSchema,
  signature_kind: v.picklist(CompletionSignatureKindValues),
});

export const CloudApiCompletionSignatureResultSchema = v.union([
  CloudApiCompletionSignatureResponseSchema,
  CloudApiUnavailableSignatureResponseSchema,
]);

// NRAS returns a list whose first entry carries the overall-attestation JWT.
// Both levels tolerate extra values because only that first JWT is part of the
// NRAS contract consumed by the SDK.
const NrasJwtEntrySchema = v.looseTuple([v.literal('JWT'), v.string()]);

export const NrasResponseSchema = v.tupleWithRest(
  [NrasJwtEntrySchema],
  v.unknown(),
);

export const NrasJwtPayloadSchema = looseObjectSchema({});

export const NrasOverallAttestationJwtClaimsSchema = looseObjectSchema({
  'x-nvidia-overall-att-result': v.boolean(),
});
