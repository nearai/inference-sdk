# TypeScript SDK API reference

This page describes the Cloud request and verification APIs exported by
`verifiable-ai-sdk`. For workflows and complete code examples, see the
[verification guide](./verification-guide.md).

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `fetchCompletionSignature` | `(params: FetchCompletionSignatureParams) => Promise<CompletionSignature>` | Fetches a completion signature. |
| `lookupCompletionSignature` | `(params: LookupCompletionSignatureParams) => Promise<CompletionSignatureLookup>` | Fetches a completion signature or an unavailable state. |
| `fetchModelAttestations` | `(params: FetchModelAttestationsParams) => Promise<FetchedModelAttestations>` | Fetches model-attestation evidence. |
| `fetchModelAttestationForSignature` | `(params: FetchModelAttestationForSignatureParams) => Promise<FetchedModelAttestation>` | Fetches model evidence selected for a `provider_tee` signer. |
| `fetchGatewayAttestation` | `(params: FetchGatewayAttestationParams) => Promise<FetchedGatewayAttestation>` | Fetches gateway-attestation evidence. |
| `verifyModelAttestation` | `(params: VerifyModelAttestationParams) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(params: VerifyModelResponseParams) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(params: VerifyGatewayAttestationParams) => Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence, its quote-bound TLS identity, and, by default, the observed TLS peer. |
| `verifyGatewayResponse` | `(params: VerifyGatewayResponseParams) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `findModelAttestationForSignature` | `(params: FindModelAttestationForSignatureParams) => ModelAttestation` | Selects the single model attestation matching a `provider_tee` signature. It does not verify evidence. |

## NEAR AI Cloud request functions

The request helpers do not send completion requests or retain completion
bytes. Each accepts one named `...Params` object with its Cloud API request
configuration and operation-specific fields at the same level.

### Shared request fields

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey` | `string` | Yes | — | Bearer token for signature and evidence requests. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Cloud API base URL. Include the API path when using a custom endpoint. |

### Functions

| Function | Params | Resolves to | Behavior |
| --- | --- | --- | --- |
| `lookupCompletionSignature(params)` | `LookupCompletionSignatureParams` | `CompletionSignatureLookup` | Returns either a signature or a service-provided unavailable state. |
| `fetchCompletionSignature(params)` | `FetchCompletionSignatureParams` | `CompletionSignature` | Returns a signature; use `lookupCompletionSignature` when the application needs to handle an unavailable state itself. |
| `fetchModelAttestations(params)` | `FetchModelAttestationsParams` | `FetchedModelAttestations` | Creates a fresh client nonce and fetches the Cloud API model-attestation response, optionally filtered by signing algorithm and signing address. Use `findModelAttestationForSignature` to bind that result to a `provider_tee` signature. |
| `fetchModelAttestationForSignature(params)` | `FetchModelAttestationForSignatureParams` | `FetchedModelAttestation` | Convenience equivalent of `fetchModelAttestations` followed by `findModelAttestationForSignature`. Requires a `provider_tee` signature and requests evidence for its signer. |
| `fetchGatewayAttestation(params)` | `FetchGatewayAttestationParams` | `FetchedGatewayAttestation` | Creates a fresh client nonce, fetches Gateway evidence, rejects a mismatched echoed nonce, and requests the Gateway TLS fingerprint. In Node, it captures the TLS peer fingerprint for that HTTPS request. |

### Operation-specific parameter fields

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `FetchCompletionSignatureParams` and `LookupCompletionSignatureParams` | `completionId` | `string` | Yes | Non-empty completion ID. |
|  | `signingAlgo?` | `SigningAlgo` | No | Signing algorithm to request. Omitting it requests the service default, `ecdsa`. |
| `FetchModelAttestationsParams` | `model` | `string` | Yes | Non-empty canonical model ID. |
|  | `signingAlgo?` | `SigningAlgo` | No | Optional signing-algorithm filter. Omit it to use the service default. |
|  | `signingAddress?` | `string` | No | Optional signing-address filter. Supply it when requesting evidence for a `provider_tee` response signature. |
| `FetchModelAttestationForSignatureParams` | `model` | `string` | Yes | Non-empty canonical model ID. |
|  | `signature` | `CompletionSignatureReference` | Yes | Signature kind and signer with `kind: 'provider_tee'`; its signer selects the result. A full `CompletionSignature` can be passed directly. |
| `FetchGatewayAttestationParams` | `signingAlgo?` | `SigningAlgo` | No | Gateway signing algorithm. Omitting it requests `ed25519`; when verifying a gateway response, use its signature's signing algorithm. This does not select a gateway instance. |

### Attestation fetch result types

Every attestation fetch helper generates and sends a fresh 32-byte client nonce
and checks the service's echoed nonce. Each result places its client values in
`clientBinding`. Pair that value with the result's attestation in the matching
attestation verifier.

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `clientBinding` | `ModelClientBinding` | Client values associated with this evidence request. Pass it to `verifyModelAttestation`. |
|  | `attestations` | `readonly ModelAttestation[]` | Cloud API `model_attestations`. The SDK currently requires exactly one item. |
| `FetchedModelAttestation` | `clientBinding` | `ModelClientBinding` | Client values associated with this evidence request. Pass it to `verifyModelAttestation`. |
|  | `attestation` | `ModelAttestation` | Model attestation selected for the requested `provider_tee` signer. |
| `FetchedGatewayAttestation` | `attestation` | `GatewayAttestation` | Returned Gateway attestation. |
|  | `clientBinding` | `GatewayClientBinding` | Client values associated with this evidence request. Pass it to `verifyGatewayAttestation`. |
| `ModelClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
| `GatewayClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `peerSpkiFingerprint?` | `string` | SHA-256 SPKI fingerprint observed for the HTTPS request that returned this evidence. Node supplies it automatically; browser fetch does not expose it, so browser verification must disable peer TLS binding. |

## Model attestation selection

### `findModelAttestationForSignature`

Use this function after `fetchModelAttestations` to select the evidence for a
`provider_tee` signature. It requires exactly one signer match but does not
verify the attestation. `fetchModelAttestationForSignature` is the convenience
form of these two operations.

#### `FindModelAttestationForSignatureParams`

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `attestations` | `readonly ModelAttestation[]` | Yes | Model attestations returned by `fetchModelAttestations`. Exactly one item must match `signature.signer`. |
| `signature` | `CompletionSignatureReference` | Yes | `provider_tee` signature whose signer is used for matching. A full `CompletionSignature` can be passed directly. |

## Verification functions

| Function | Params | Returns | Description |
| --- | --- | --- | --- |
| `verifyModelAttestation(params)` | `VerifyModelAttestationParams` | `Promise<VerifiedModelAttestation>` | Verifies model attestation evidence and optional GPU evidence. |
| `verifyModelResponse(params)` | `VerifyModelResponseParams` | `void` | Verifies the exact completion bytes, a `provider_tee` signature, and the supplied model-attestation signer. |
| `verifyGatewayAttestation(params)` | `VerifyGatewayAttestationParams` | `Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence and its quote-bound TLS identity. By default, it requires and checks `clientBinding.peerSpkiFingerprint`. |
| `verifyGatewayResponse(params)` | `VerifyGatewayResponseParams` | `void` | Verifies the exact completion bytes, a `gateway` signature, and the supplied gateway-attestation signer. |

### Attestation verification parameters

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelAttestationParams` | `attestation` | `ModelAttestation` | Yes | Raw model evidence. |
|  | `clientBinding` | `ModelClientBinding` | Yes | Client values returned by the matching model-attestation fetch result. |
|  | `policy?` | `ModelAttestationPolicy` | No | TCB and GPU evidence requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and NVIDIA verifier overrides. |
| `VerifyGatewayAttestationParams` | `attestation` | `GatewayAttestation` | Yes | Raw gateway evidence. |
|  | `clientBinding` | `GatewayClientBinding` | Yes | Client values returned with the matching Gateway-attestation fetch result. |
|  | `policy?` | `GatewayAttestationPolicy` | No | TCB and peer TLS binding requirements. |
|  | `verifiers?` | `AttestationVerifiers` | No | Quote and deployment verifier overrides. |

`clientBinding.nonce` must be the nonce returned with the matching evidence.
`verifyPeerTlsBinding` defaults to `true`: a missing peer fingerprint fails
verification, and a supplied one must match the fingerprint authenticated by
the quote. Set it to `false` for browser fetch. The SDK then ignores any peer
fingerprint, still verifies the nonce and quote-bound TLS identity, and returns
an `attested` TLS binding.

`verifyGatewayResponse` verifies gateway-service provenance and integrity for
the exact completion bytes. It matches the signature to the signer bound to
verified gateway deployment evidence; it does not establish model execution.

### Response verification parameters

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelResponseParams` | `requestBody` | `Uint8Array` | Yes | Exact bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'provider_tee'`. |
|  | `attestation` | `VerifiedModelAttestation` | Yes | Successful model-attestation result whose signer must match the signature. |
| `VerifyGatewayResponseParams` | `requestBody` | `Uint8Array` | Yes | Exact bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'gateway'`. |
|  | `attestation` | `VerifiedGatewayAttestation` | Yes | Successful gateway-attestation result whose signer must match the signature. |

Call the matching attestation verifier before response verification. Results are
ordinary data, so callers decide when raw evidence must be verified again after
storage, transfer, or reconstruction in another language.

## Signatures and raw evidence

### Signature kinds

`CompletionSignature.kind` is Cloud API's explicit verification-path
discriminant. The two values represent different trust boundaries and produce
different guarantees after response verification.

| Kind | Signed at | Required verified evidence | A successful response verification establishes |
| --- | --- | --- | --- |
| `provider_tee` | Model-serving TEE | `VerifiedModelAttestation` | A verified model TEE signer signed the exact request and response bytes. |
| `gateway` | NEAR AI Cloud Gateway TEE | `VerifiedGatewayAttestation` | A verified Gateway signer signed the exact client-visible request and response bytes. It does not establish model execution. |

Cloud API can return `gateway` when it rewrites the client-visible response,
because a byte-exact provider signature would no longer match those bytes.

### Completion signatures

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `signingAlgo` | `SigningAlgo` | Signing algorithm. |
|  | `signingAddress` | `string` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignature` | `kind` | `'provider_tee' \| 'gateway'` | Explicit Cloud API signature kind that selects the matching evidence and response verifier. |
|  | `signedText` | `string` | Text covered by the signature. |
|  | `signature` | `string` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
|  | `signer` | `SigningIdentity` | Signing identity that must match verified evidence. |
| `CompletionSignatureReference` | `kind` | `'provider_tee' \| 'gateway'` | Signature kind. `findModelAttestationForSignature` accepts only `provider_tee`. |
|  | `signer` | `SigningIdentity` | Signing identity used when selecting evidence. |

`CompletionSignatureKind` is the union `'provider_tee' | 'gateway'`.
`SigningAlgo` is the union `'ecdsa' | 'ed25519'`.

### Completion signature lookup

| Type or variant | Field | Type | Description |
| --- | --- | --- | --- |
| `CompletionSignatureLookup` | `status` | `'found' \| 'unavailable'` | Discriminant. |
| `CompletionSignatureLookup` when `status === 'found'` | `signature` | `CompletionSignature` | Returned completion signature. |
| `CompletionSignatureLookup` when `status === 'unavailable'` | `unavailable` | `SignatureUnavailable` | Service-provided unavailable state from a 2xx response. |
| `SignatureUnavailable` | `errorCode` | `string` | Service error code. |
|  | `message` | `string` | Service message. |

### Attestation evidence

`AttestationEventLog` is `string | readonly unknown[]`.

| Field | Type | Description |
| --- | --- | --- |
| `nonce` | `string` | Nonce echoed by the service. The fetch helper validates it against, and separately returns, its client nonce. |
| `signer` | `SigningIdentity` | Advertised signing identity. |
| `intelQuote` | `string` | Intel TDX quote. |
| `eventLog` | `AttestationEventLog` | Input used to replay RTMR3 measurements. |
| `appCompose` | `string` | Measured compose configuration text. |
| `declaredSpkiFingerprint?` | `string` | Optional service-declared SPKI fingerprint for model evidence; Gateway evidence requires it. It is not a caller-observed TLS peer. |

`AttestationEvidence` contains the fields above. `ModelAttestation` and
`GatewayAttestation` extend it as follows:

| Type | Additional field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `ModelAttestation` | `reportedQuoteData?` | `string` | No | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidiaPayload?` | `string` | No | GPU attestation payload. |
| `GatewayAttestation` | `declaredSpkiFingerprint` | `string` | Yes | Gateway TLS SPKI fingerprint authenticated by the quote. |
|  | `reportedQuoteData` | `string` | Yes | Gateway report-data copy. |

## Policies and verifier callbacks

### Policies

| Type | Field | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `AttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
| `ModelAttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
|  | `gpuEvidence?` | `'if-present' \| 'required'` | `'if-present'` | Whether a model report without GPU evidence is accepted. |
| `GatewayAttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
|  | `verifyPeerTlsBinding?` | `boolean` | `true` | Require and verify the observed TLS peer fingerprint. Set to `false` only when no peer fingerprint is available, such as browser fetch; verification then returns an `attested` TLS binding. |

`TcbStatus` is one of `UpToDate`, `SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`, `Revoked`, or `Unknown`.

### Verifier bags and callbacks

| Type | Field or signature | Description |
| --- | --- | --- |
| `AttestationVerifiers` | `quote?: QuoteVerifier` | Replaces the built-in Intel DCAP quote verifier. |
|  | `deployment?: DeploymentVerifier` | Applies caller-defined deployment acceptance. |
| `ModelAttestationVerifiers` | `quote?: QuoteVerifier` | Replaces the built-in Intel DCAP quote verifier. |
|  | `deployment?: DeploymentVerifier` | Applies caller-defined deployment acceptance. |
|  | `nvidia?: NvidiaEvidenceVerifier` | Replaces the default NVIDIA NRAS verifier. |
| `QuoteVerifier` | `(quote: string) => Awaitable<QuoteVerificationResult>` | Authenticates a quote and returns the verified quote fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) => Awaitable<void>` | Resolves only for an accepted deployment. |
| `NvidiaEvidenceVerifier` | `(payload: string) => Awaitable<void>` | Resolves only for accepted GPU evidence. |

The default NVIDIA verifier submits GPU evidence to NVIDIA NRAS over HTTPS and
accepts its documented boolean overall result. It does not locally validate the
returned JWT/EAT signature. Provide `nvidia` when the application needs local
JWT/EAT validation, different trust roots, or another verification service.

### Quote and deployment values

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `QuoteVerificationResult` | `tcbStatus` | `TcbStatus` | Authenticated TCB status. |
|  | `advisoryIds` | `readonly string[]` | Authenticated advisory IDs. |
|  | `debugEnabled` | `boolean` | Whether the authenticated quote enables debug mode. |
|  | `reportData` | `Uint8Array` | Authenticated quote report data. |
|  | `mrConfigId` | `Uint8Array` | Authenticated quote MRCONFIGID. |
|  | `rtMr3` | `Uint8Array` | Authenticated quote RTMR3. |
| `MeasuredDeployment` | `readonly appCompose` | `string` | Configuration text bound to MRCONFIGID. |
|  | `readonly runtimeMeasurements` | `RuntimeMeasurements` | Runtime measurements derived from verified event-log entries. |
| `RuntimeMeasurements` | `readonly osImageHash?` | `string` | Optional measured OS image hash. |
|  | `readonly composeHash?` | `string` | Optional measured compose hash. |

## Verified results

`VerifiedAttestationEvidence` is shared by both verified attestation results.

| Field | Type | Description |
| --- | --- | --- |
| `signer` | `Readonly<SigningIdentity>` | Verified signing identity. |
| `tcbStatus` | `TcbStatus` | Accepted TCB status. |
| `advisoryIds` | `readonly string[]` | Quote advisory IDs. |
| `deployment` | `MeasuredDeployment` | Verified deployment measurements. |
| `deploymentProvenance` | `DeploymentProvenanceStatus` | Whether a supplied `DeploymentVerifier` accepted the deployment. |

| Type | Additional field | Type | Description |
| --- | --- | --- | --- |
| `VerifiedModelAttestation` | `tlsBinding` | `ModelTlsBinding` | Verified model TLS binding. |
|  | `gpuEvidence` | `GpuEvidenceStatus` | GPU evidence result. |
| `VerifiedGatewayAttestation` | `tlsBinding` | `GatewayTlsBinding` | Verified gateway TLS binding. |

| Alias | Definition |
| --- | --- |
| `ModelTlsBinding` | `{ kind: 'none' } \| { kind: 'declared'; spkiFingerprint: string }` |
| `GatewayTlsBinding` | `{ kind: 'attested'; spkiFingerprint: string } \| { kind: 'peer'; spkiFingerprint: string }` |
| `GpuEvidenceStatus` | `'not_provided' \| 'verified'` |
| `DeploymentProvenanceStatus` | `'not_checked' \| 'verified'` |
