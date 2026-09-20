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

function isNonArrayObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const Uint8ArraySchema = v.custom<Uint8Array>(isUint8Array);
const NonArrayObjectSchema =
  v.custom<Record<string, unknown>>(isNonArrayObject);

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
  stream: v.pipe(
    v.optional(v.nullable(v.boolean())),
    v.transform((value) => value ?? undefined),
  ),
});

export const CompletionResponseIdSchema = objectSchema({
  id: v.pipe(v.string(), v.minLength(1)),
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

export const OhttpAttestationSchema = objectSchema({
  signing_algo: v.literal('ed25519'),
  signing_key: v.string(),
  key_config: v.string(),
  signature: v.string(),
});

const OptionalOhttpAttestationSchema = v.pipe(
  v.optional(v.nullable(OhttpAttestationSchema)),
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

const CloudApiModelAttestationEntries = {
  ...CloudApiAttestationEntries,
  nvidia_payload: OptionalCloudApiStringSchema,
  signing_public_key: OptionalCloudApiStringSchema,
};

export const CloudApiModelAttestationSchema = objectSchema(
  CloudApiModelAttestationEntries,
);

const DirectApiModelAttestationEntries = {
  ...CloudApiModelAttestationEntries,
  model_name: v.pipe(v.string(), v.minLength(1)),
  info: objectSchema({
    tcb_info: v.union([CloudApiTcbInfoSchema, CloudApiTcbInfoJsonSchema]),
    instance_id: OptionalCloudApiStringSchema,
  }),
};

export const DirectApiModelAttestationSchema = objectSchema(
  DirectApiModelAttestationEntries,
);

export const DirectApiAttestationReportSchema = objectSchema({
  ...DirectApiModelAttestationEntries,
  all_attestations: v.pipe(
    v.array(DirectApiModelAttestationSchema),
    v.minLength(1),
  ),
  compose_manager_attestation: v.optional(v.unknown()),
  ohttp_attestation: OptionalOhttpAttestationSchema,
});

export const CloudApiGatewayAttestationSchema = objectSchema({
  ...CloudApiAttestationEntries,
  report_data: v.string(),
});

export const CloudApiModelAttestationResponseSchema = objectSchema({
  // Cloud API omits this field when no model provider produced evidence.
  // Normalize that wire form to an empty candidate collection.
  model_attestations: v.optional(v.array(CloudApiModelAttestationSchema), []),
});

export const CloudApiGatewayAttestationResponseSchema = objectSchema({
  gateway_attestation: CloudApiGatewayAttestationSchema,
  ohttp_attestation: OptionalOhttpAttestationSchema,
});

// This is the minimal external boundary for secure Chat Completions requests.
// The inference client knows how to encrypt selected protocol fields, but leaves
// ordinary and future Chat fields to the Gateway and model to interpret.
export const ChatCompletionRequestSchema = looseObjectSchema({
  model: v.pipe(v.string(), v.minLength(1)),
});

// The server can add valid OpenAI-compatible fields faster than the SDK can
// learn to transform them. These schemas only establish that a response/event
// is a JSON object; the E2EE transformer selectively decrypts documented
// fields and preserves everything else.
export const SecureChatCompletionResponseSchema =
  v.custom<Record<string, unknown>>(isNonArrayObject);

export const SecureChatCompletionStreamChunkSchema =
  v.custom<Record<string, unknown>>(isNonArrayObject);

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

export const DirectApiCompletionSignatureResultSchema = v.union([
  objectSchema({
    text: v.string(),
    signature: v.string(),
    signing_address: v.string(),
    signing_algo: SigningAlgoSchema,
    // Direct provider signatures do not carry a kind discriminator. An
    // explicit Gateway discriminator must not be silently reinterpreted.
    signature_kind: v.optional(v.literal('provider_tee')),
  }),
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

export const NrasOverallAttestationJwtClaimsSchema = looseObjectSchema({
  'x-nvidia-overall-att-result': v.boolean(),
  eat_nonce: v.pipe(v.string(), v.regex(/^[0-9a-fA-F]{64}$/)),
  exp: v.pipe(v.number(), v.integer()),
  nbf: v.pipe(v.number(), v.integer()),
  iat: v.pipe(v.number(), v.integer()),
});

export const NvidiaJwksSchema = v.object({
  keys: v.array(
    looseObjectSchema({ kty: v.string(), kid: v.optional(v.string()) }),
  ),
});

// GitHub transports opaque Sigstore bundles. The cryptographic verifier owns
// their interpretation; this schema checks the DSSE wire shape at its boundary.
export const GitHubImageAttestationsSchema = objectSchema({
  attestations: v.array(
    objectSchema({ bundle: v.record(v.string(), v.unknown()) }),
  ),
});

const SigstoreCertificateSchema = objectSchema({ rawBytes: v.string() });
const SigstoreTlogEntrySchema = objectSchema({
  logIndex: v.string(),
  logId: objectSchema({ keyId: v.string() }),
  kindVersion: objectSchema({ kind: v.string(), version: v.string() }),
  // Sigstore's wire/library contract uses null for Rekor v2's absent timestamp.
  integratedTime: v.nullish(v.string(), null),
  inclusionPromise: v.optional(
    objectSchema({ signedEntryTimestamp: v.string() }),
  ),
  inclusionProof: v.optional(
    objectSchema({
      logIndex: v.string(),
      rootHash: v.string(),
      treeSize: v.string(),
      hashes: v.array(v.string()),
      checkpoint: objectSchema({ envelope: v.string() }),
    }),
  ),
  canonicalizedBody: v.string(),
});

export const DeploymentAppComposeSchema = objectSchema({
  docker_compose_file: v.string(),
});

export const DeploymentDockerComposeSchema = objectSchema({
  services: v.record(
    v.string(),
    objectSchema({
      image: v.pipe(
        v.nullish(v.string()),
        v.transform((value) => value ?? undefined),
      ),
    }),
  ),
});

export const ImageProvenanceBundleSchema = objectSchema({
  mediaType: v.picklist([
    'application/vnd.dev.sigstore.bundle+json;version=0.1',
    'application/vnd.dev.sigstore.bundle+json;version=0.2',
    'application/vnd.dev.sigstore.bundle+json;version=0.3',
    'application/vnd.dev.sigstore.bundle.v0.3+json',
  ]),
  verificationMaterial: objectSchema({
    certificate: v.optional(SigstoreCertificateSchema),
    x509CertificateChain: v.optional(
      objectSchema({
        certificates: v.pipe(
          v.array(SigstoreCertificateSchema),
          v.minLength(1),
        ),
      }),
    ),
    tlogEntries: v.pipe(v.array(SigstoreTlogEntrySchema), v.minLength(1)),
    timestampVerificationData: v.optional(
      objectSchema({
        rfc3161Timestamps: v.optional(
          v.array(objectSchema({ signedTimestamp: v.string() })),
          () => [],
        ),
      }),
    ),
  }),
  dsseEnvelope: objectSchema({
    payload: v.string(),
    payloadType: v.literal('application/vnd.in-toto+json'),
    signatures: v.pipe(
      v.array(objectSchema({ sig: v.string(), keyid: v.optional(v.string()) })),
      v.length(1),
    ),
  }),
});

const ProvenanceStatementEntries = {
  _type: v.picklist([
    'https://in-toto.io/Statement/v1',
    'https://in-toto.io/Statement/v0.1',
  ]),
  subject: v.array(
    objectSchema({
      digest: v.record(v.string(), v.string()),
    }),
  ),
};

export const ImageProvenanceStatementSchema = v.union([
  objectSchema({
    ...ProvenanceStatementEntries,
    predicateType: v.literal('https://slsa.dev/provenance/v1'),
    predicate: objectSchema({
      buildDefinition: objectSchema({
        externalParameters: objectSchema({
          workflow: objectSchema({
            repository: v.string(),
            path: v.string(),
            ref: v.string(),
          }),
        }),
        resolvedDependencies: v.array(
          objectSchema({
            uri: v.string(),
            digest: v.optional(v.record(v.string(), v.string()), () => ({})),
          }),
        ),
      }),
    }),
  }),
  objectSchema({
    ...ProvenanceStatementEntries,
    predicateType: v.literal('https://slsa.dev/provenance/v0.2'),
    predicate: objectSchema({
      invocation: objectSchema({
        configSource: objectSchema({
          uri: v.string(),
          entryPoint: v.string(),
          digest: v.record(v.string(), v.string()),
        }),
      }),
    }),
  }),
]);
