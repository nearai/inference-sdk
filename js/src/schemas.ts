import * as v from 'valibot';

/** Values accepted by the NEAR AI attestation and completion APIs. */
export const SigningAlgorithmValues = ['ecdsa', 'ed25519'] as const;
export const CompletionSignatureKindValues = [
  'provider_tee',
  'gateway',
] as const;
export const TcbStatusValues = [
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
export type SigningAlgorithmSchema = typeof SigningAlgorithmSchema;
export type SigningAlgorithm = v.InferOutput<SigningAlgorithmSchema>;

export const CompletionSignatureKindSchema = v.picklist(
  CompletionSignatureKindValues,
);
export type CompletionSignatureKindSchema =
  typeof CompletionSignatureKindSchema;
export type CompletionSignatureKind =
  v.InferOutput<CompletionSignatureKindSchema>;

export const TcbStatusSchema = v.picklist(TcbStatusValues);
export type TcbStatusSchema = typeof TcbStatusSchema;
export type TcbStatus = v.InferOutput<TcbStatusSchema>;

/** A value that an SDK callback may produce synchronously or asynchronously. */
export type Awaitable<TValue> = TValue | PromiseLike<TValue>;

function isFunction(value: unknown): boolean {
  return typeof value === 'function';
}

function isUint8Array(value: unknown): boolean {
  return value instanceof Uint8Array;
}

type PlainObject = object;
type NonArrayObject = object;

function isPlainObject(value: unknown): value is PlainObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isNonArrayObject(value: unknown): value is NonArrayObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const Uint8ArraySchema = v.custom<Uint8Array>(isUint8Array);
const PlainObjectSchema = v.custom<PlainObject>(isPlainObject);
const NonArrayObjectSchema = v.custom<NonArrayObject>(isNonArrayObject);

function objectSchema<TEntries extends v.ObjectEntries>(entries: TEntries) {
  return v.intersect([v.object(entries), PlainObjectSchema] as const);
}

function strictObjectSchema<TEntries extends v.ObjectEntries>(
  entries: TEntries,
) {
  return v.intersect([v.strictObject(entries), PlainObjectSchema] as const);
}

// ---------------------------------------------------------------------------
// Normalized SDK data passed across public verification boundaries
// ---------------------------------------------------------------------------

export const SigningIdentitySchema = strictObjectSchema({
  algorithm: SigningAlgorithmSchema,
  address: v.string(),
});
export type SigningIdentitySchema = typeof SigningIdentitySchema;
export type SigningIdentity = v.InferOutput<SigningIdentitySchema>;

export const AttestationEventLogSchema = v.union([
  v.string(),
  v.pipe(v.array(v.unknown()), v.readonly()),
]);
export type AttestationEventLogSchema = typeof AttestationEventLogSchema;
export type AttestationEventLog = v.InferOutput<AttestationEventLogSchema>;

const AttestationEvidenceEntries = {
  nonce: v.string(),
  signer: SigningIdentitySchema,
  intelQuote: v.string(),
  eventLog: AttestationEventLogSchema,
  appCompose: v.string(),
  declaredSpkiFingerprint: v.optional(v.nullable(v.string())),
  reportedQuoteData: v.optional(v.string()),
};

export const AttestationEvidenceSchema = strictObjectSchema(
  AttestationEvidenceEntries,
);
export type AttestationEvidenceSchema = typeof AttestationEvidenceSchema;
export type AttestationEvidence = v.InferOutput<AttestationEvidenceSchema>;

// Internal extraction accepts endpoint-specific evidence extensions after the
// public model/gateway input schema has already rejected unknown user fields.
export const AttestationEvidenceBaseSchema = objectSchema(
  AttestationEvidenceEntries,
);
export type AttestationEvidenceBaseSchema =
  typeof AttestationEvidenceBaseSchema;

export const ModelAttestationSchema = strictObjectSchema({
  ...AttestationEvidenceEntries,
  nvidiaPayload: v.optional(v.nullable(v.string())),
});
export type ModelAttestationSchema = typeof ModelAttestationSchema;
export type ModelAttestation = v.InferOutput<ModelAttestationSchema>;

export const GatewayAttestationSchema = strictObjectSchema({
  ...AttestationEvidenceEntries,
  reportedQuoteData: v.string(),
});
export type GatewayAttestationSchema = typeof GatewayAttestationSchema;
export type GatewayAttestation = v.InferOutput<GatewayAttestationSchema>;

export const CompletionBytesSchema = strictObjectSchema({
  requestBody: Uint8ArraySchema,
  responseBody: Uint8ArraySchema,
});
export type CompletionBytesSchema = typeof CompletionBytesSchema;
export type CompletionBytes = v.InferOutput<CompletionBytesSchema>;

export const CompletionSignatureSchema = strictObjectSchema({
  signedText: v.string(),
  signature: v.string(),
  signer: SigningIdentitySchema,
  kind: CompletionSignatureKindSchema,
});
export type CompletionSignatureSchema = typeof CompletionSignatureSchema;
export type CompletionSignature = v.InferOutput<CompletionSignatureSchema>;

export const SignatureUnavailableSchema = strictObjectSchema({
  errorCode: v.string(),
  message: v.string(),
});
export type SignatureUnavailableSchema = typeof SignatureUnavailableSchema;
export type SignatureUnavailable = v.InferOutput<SignatureUnavailableSchema>;

const CompletionSignatureFoundSchema = strictObjectSchema({
  status: v.literal('found'),
  signature: CompletionSignatureSchema,
});

const CompletionSignatureUnavailableSchema = strictObjectSchema({
  status: v.literal('unavailable'),
  unavailable: SignatureUnavailableSchema,
});

export const CompletionSignatureLookupSchema = v.union([
  CompletionSignatureFoundSchema,
  CompletionSignatureUnavailableSchema,
]);
export type CompletionSignatureLookupSchema =
  typeof CompletionSignatureLookupSchema;
export type CompletionSignatureLookup =
  v.InferOutput<CompletionSignatureLookupSchema>;

export const RuntimeMeasurementsSchema = v.pipe(
  strictObjectSchema({
    osImageHash: v.optional(v.string()),
    composeHash: v.optional(v.string()),
  }),
  v.readonly(),
);
export type RuntimeMeasurementsSchema = typeof RuntimeMeasurementsSchema;
export type RuntimeMeasurements = v.InferOutput<RuntimeMeasurementsSchema>;

export const MeasuredDeploymentSchema = v.pipe(
  strictObjectSchema({
    appCompose: v.string(),
    runtimeMeasurements: RuntimeMeasurementsSchema,
  }),
  v.readonly(),
);
export type MeasuredDeploymentSchema = typeof MeasuredDeploymentSchema;
export type MeasuredDeployment = v.InferOutput<MeasuredDeploymentSchema>;

export const QuoteVerificationResultSchema = objectSchema({
  tcbStatus: TcbStatusSchema,
  advisoryIds: v.pipe(v.array(v.string()), v.readonly()),
  debugEnabled: v.boolean(),
  reportData: Uint8ArraySchema,
  mrConfigId: Uint8ArraySchema,
  rtMr3: Uint8ArraySchema,
});
export type QuoteVerificationResultSchema =
  typeof QuoteVerificationResultSchema;
export type QuoteVerificationResult =
  v.InferOutput<QuoteVerificationResultSchema>;

export type QuoteVerifier = (
  quote: string,
) => Awaitable<QuoteVerificationResult>;
export type NvidiaEvidenceVerifier = (payload: string) => Awaitable<void>;
export type DeploymentVerifier = (
  deployment: MeasuredDeployment,
) => Awaitable<void>;

export const QuoteVerifierSchema = v.custom<QuoteVerifier>(isFunction);
export type QuoteVerifierSchema = typeof QuoteVerifierSchema;

export const NvidiaEvidenceVerifierSchema =
  v.custom<NvidiaEvidenceVerifier>(isFunction);
export type NvidiaEvidenceVerifierSchema = typeof NvidiaEvidenceVerifierSchema;

export const DeploymentVerifierSchema =
  v.custom<DeploymentVerifier>(isFunction);
export type DeploymentVerifierSchema = typeof DeploymentVerifierSchema;

export const AttestationPolicySchema = strictObjectSchema({
  acceptedTcbStatuses: v.optional(
    v.pipe(v.array(TcbStatusSchema), v.readonly()),
  ),
});
export type AttestationPolicySchema = typeof AttestationPolicySchema;
export type AttestationPolicy = v.InferOutput<AttestationPolicySchema>;

export const AttestationPolicyBaseSchema = objectSchema({
  acceptedTcbStatuses: v.optional(
    v.pipe(v.array(TcbStatusSchema), v.readonly()),
  ),
});
export type AttestationPolicyBaseSchema = typeof AttestationPolicyBaseSchema;

export const ModelAttestationPolicySchema = strictObjectSchema({
  acceptedTcbStatuses: v.optional(
    v.pipe(v.array(TcbStatusSchema), v.readonly()),
  ),
  gpuEvidence: v.optional(v.picklist(['if-present', 'required'] as const)),
});
export type ModelAttestationPolicySchema = typeof ModelAttestationPolicySchema;
export type ModelAttestationPolicy =
  v.InferOutput<ModelAttestationPolicySchema>;

export const AttestationVerifiersSchema = strictObjectSchema({
  quote: v.optional(QuoteVerifierSchema),
  deployment: v.optional(DeploymentVerifierSchema),
});
export type AttestationVerifiersSchema = typeof AttestationVerifiersSchema;
export type AttestationVerifiers = v.InferOutput<AttestationVerifiersSchema>;

export const ModelAttestationVerifiersSchema = strictObjectSchema({
  quote: v.optional(QuoteVerifierSchema),
  deployment: v.optional(DeploymentVerifierSchema),
  nvidia: v.optional(NvidiaEvidenceVerifierSchema),
});
export type ModelAttestationVerifiersSchema =
  typeof ModelAttestationVerifiersSchema;
export type ModelAttestationVerifiers =
  v.InferOutput<ModelAttestationVerifiersSchema>;

export const VerifyModelAttestationInputSchema = strictObjectSchema({
  attestation: ModelAttestationSchema,
  nonce: v.string(),
  policy: v.optional(ModelAttestationPolicySchema),
  verifiers: v.optional(ModelAttestationVerifiersSchema),
});
export type VerifyModelAttestationInputSchema =
  typeof VerifyModelAttestationInputSchema;
export type VerifyModelAttestationInput =
  v.InferOutput<VerifyModelAttestationInputSchema>;

export const VerifyGatewayAttestationInputSchema = strictObjectSchema({
  attestation: GatewayAttestationSchema,
  nonce: v.string(),
  policy: v.optional(AttestationPolicySchema),
  verifiers: v.optional(AttestationVerifiersSchema),
  peerSpkiFingerprint: v.string(),
});
export type VerifyGatewayAttestationInputSchema =
  typeof VerifyGatewayAttestationInputSchema;
export type VerifyGatewayAttestationInput =
  v.InferOutput<VerifyGatewayAttestationInputSchema>;

const ModelResponseInputEntries = {
  requestBody: Uint8ArraySchema,
  responseBody: Uint8ArraySchema,
  signature: CompletionSignatureSchema,
  // Verification of this opaque, in-memory capability is performed by the
  // WeakMap-backed verifier rather than by a structural schema.
  attestation: v.unknown(),
};

export const VerifyModelResponseFieldsSchema = strictObjectSchema(
  ModelResponseInputEntries,
);
export type VerifyModelResponseFieldsSchema =
  typeof VerifyModelResponseFieldsSchema;
export type VerifyModelResponseFields =
  v.InferOutput<VerifyModelResponseFieldsSchema>;

export const VerifyGatewayResponseFieldsSchema = strictObjectSchema(
  ModelResponseInputEntries,
);
export type VerifyGatewayResponseFieldsSchema =
  typeof VerifyGatewayResponseFieldsSchema;
export type VerifyGatewayResponseFields =
  v.InferOutput<VerifyGatewayResponseFieldsSchema>;

// ---------------------------------------------------------------------------
// NEAR AI Cloud client inputs and HTTP response shapes
// ---------------------------------------------------------------------------

export type NearAiCloudFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Awaitable<Response>;

export const NearAiCloudFetchSchema = v.custom<NearAiCloudFetch>(isFunction);
export type NearAiCloudFetchSchema = typeof NearAiCloudFetchSchema;

export const NearAiCloudClientOptionsSchema = strictObjectSchema({
  baseUrl: v.optional(v.string()),
  apiKey: v.string(),
  fetch: v.optional(NearAiCloudFetchSchema),
});
export type NearAiCloudClientOptionsSchema =
  typeof NearAiCloudClientOptionsSchema;
export type NearAiCloudClientOptions =
  v.InferInput<NearAiCloudClientOptionsSchema>;

export const FetchModelAttestationsInputSchema = strictObjectSchema({
  model: v.string(),
  nonce: v.string(),
  algorithm: v.optional(SigningAlgorithmSchema),
  signingAddress: v.optional(v.string()),
});
export type FetchModelAttestationsInputSchema =
  typeof FetchModelAttestationsInputSchema;
export type FetchModelAttestationsInput =
  v.InferOutput<FetchModelAttestationsInputSchema>;

export const FetchModelAttestationForSignatureInputSchema = strictObjectSchema({
  model: v.string(),
  nonce: v.string(),
  signature: CompletionSignatureSchema,
});
export type FetchModelAttestationForSignatureInputSchema =
  typeof FetchModelAttestationForSignatureInputSchema;
export type FetchModelAttestationForSignatureInput =
  v.InferOutput<FetchModelAttestationForSignatureInputSchema>;

export const FindModelAttestationForSignerInputSchema = strictObjectSchema({
  attestations: v.pipe(v.array(ModelAttestationSchema), v.readonly()),
  signer: SigningIdentitySchema,
});
export type FindModelAttestationForSignerInputSchema =
  typeof FindModelAttestationForSignerInputSchema;
export type FindModelAttestationForSignerInput =
  v.InferOutput<FindModelAttestationForSignerInputSchema>;

export const FetchGatewayAttestationInputSchema = strictObjectSchema({
  nonce: v.string(),
  algorithm: v.optional(SigningAlgorithmSchema),
});
export type FetchGatewayAttestationInputSchema =
  typeof FetchGatewayAttestationInputSchema;
export type FetchGatewayAttestationInput =
  v.InferOutput<FetchGatewayAttestationInputSchema>;

export const FetchCompletionSignatureInputSchema = strictObjectSchema({
  completionId: v.string(),
  algorithm: v.optional(SigningAlgorithmSchema),
});
export type FetchCompletionSignatureInputSchema =
  typeof FetchCompletionSignatureInputSchema;
export type FetchCompletionSignatureInput =
  v.InferOutput<FetchCompletionSignatureInputSchema>;

/** Minimal response surface the client consumes from an injected transport. */
export type ResponseLike = {
  ok: boolean;
  status: number;
  text: () => Awaitable<string>;
};

export const ResponseLikeSchema = v.pipe(
  NonArrayObjectSchema,
  v.object({
    ok: v.boolean(),
    status: v.number(),
    text: v.custom<ResponseLike['text']>(isFunction),
  }),
);
export type ResponseLikeSchema = typeof ResponseLikeSchema;

export const ResponseBodySchema = v.string();
export type ResponseBodySchema = typeof ResponseBodySchema;

export const CloudApiTcbInfoSchema = objectSchema({
  app_compose: v.string(),
});
export type CloudApiTcbInfoSchema = typeof CloudApiTcbInfoSchema;
export type CloudApiTcbInfo = v.InferOutput<CloudApiTcbInfoSchema>;

export const CloudApiInfoSchema = objectSchema({
  tcb_info: v.union([v.string(), CloudApiTcbInfoSchema]),
});
export type CloudApiInfoSchema = typeof CloudApiInfoSchema;
export type CloudApiInfo = v.InferOutput<CloudApiInfoSchema>;

export const CloudApiAttestationInfoEnvelopeSchema = objectSchema({
  info: v.optional(v.unknown()),
});
export type CloudApiAttestationInfoEnvelopeSchema =
  typeof CloudApiAttestationInfoEnvelopeSchema;

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
export type CloudApiModelAttestationSchema =
  typeof CloudApiModelAttestationSchema;
export type CloudApiModelAttestation =
  v.InferOutput<CloudApiModelAttestationSchema>;

export const CloudApiGatewayAttestationSchema = objectSchema({
  ...CloudApiAttestationEntries,
  report_data: v.string(),
});
export type CloudApiGatewayAttestationSchema =
  typeof CloudApiGatewayAttestationSchema;
export type CloudApiGatewayAttestation =
  v.InferOutput<CloudApiGatewayAttestationSchema>;

export const CloudApiModelAttestationResponseSchema = objectSchema({
  model_attestations: v.array(v.unknown()),
});
export type CloudApiModelAttestationResponseSchema =
  typeof CloudApiModelAttestationResponseSchema;
export type CloudApiModelAttestationResponse =
  v.InferOutput<CloudApiModelAttestationResponseSchema>;

export const CloudApiGatewayAttestationResponseSchema = objectSchema({
  gateway_attestation: v.unknown(),
});
export type CloudApiGatewayAttestationResponseSchema =
  typeof CloudApiGatewayAttestationResponseSchema;
export type CloudApiGatewayAttestationResponse =
  v.InferOutput<CloudApiGatewayAttestationResponseSchema>;

export const CloudApiUnavailableSignatureResponseSchema = objectSchema({
  error_code: v.string(),
  message: v.string(),
});
export type CloudApiUnavailableSignatureResponseSchema =
  typeof CloudApiUnavailableSignatureResponseSchema;
export type CloudApiUnavailableSignatureResponse =
  v.InferOutput<CloudApiUnavailableSignatureResponseSchema>;

export const CloudApiCompletionSignatureResponseSchema = objectSchema({
  text: v.string(),
  signature: v.string(),
  signing_address: v.string(),
  signing_algo: SigningAlgorithmSchema,
  // A strict parser below preserves the API's dedicated signature-kind error
  // contract instead of collapsing it into a generic wire-schema error.
  signature_kind: v.optional(v.unknown()),
});
export type CloudApiCompletionSignatureResponseSchema =
  typeof CloudApiCompletionSignatureResponseSchema;
export type CloudApiCompletionSignatureResponse =
  v.InferOutput<CloudApiCompletionSignatureResponseSchema>;
