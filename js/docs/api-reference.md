# TypeScript SDK API reference

This page describes the Cloud request and verification APIs exported by
`verification-sdk`. For workflows and complete code examples, see the
[verification guide](./verification-guide.md).

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `fetchCompletionSignature` | `(cloud: NearAiCloudOptions, input: FetchCompletionSignatureInput) => Promise<CompletionSignature>` | Fetches a completion signature. |
| `lookupCompletionSignature` | `(cloud: NearAiCloudOptions, input: FetchCompletionSignatureInput) => Promise<CompletionSignatureLookup>` | Fetches a completion signature or an unavailable state. |
| `fetchModelAttestations` | `(cloud: NearAiCloudOptions, input: FetchModelAttestationsInput) => Promise<FetchedModelAttestations>` | Fetches model-attestation evidence. |
| `fetchModelAttestationForSignature` | `(cloud: NearAiCloudOptions, input: FetchModelAttestationForSignatureInput) => Promise<FetchedModelAttestation>` | Fetches model evidence selected for a `provider_tee` signer. |
| `fetchGatewayAttestation` | `(cloud: NearAiCloudOptions, input?: FetchGatewayAttestationInput) => Promise<FetchedGatewayAttestation>` | Fetches gateway-attestation evidence. |
| `verifyModelAttestation` | `(input: VerifyModelAttestationInput) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(input: VerifyModelResponseInput) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(input: VerifyGatewayAttestationInput) => Promise<VerifiedGatewayAttestation>` | Verifies gateway evidence and a caller-observed TLS peer binding. |
| `verifyGatewayResponse` | `(input: VerifyGatewayResponseInput) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `findModelAttestationForSignature` | `(input: FindModelAttestationForSignatureInput) => ModelAttestation` | Selects the single model attestation matching a `provider_tee` signature. It does not verify evidence. |

## NEAR AI Cloud request functions

The request helpers do not send completion requests or retain completion
bytes. Each takes `cloud: NearAiCloudOptions` first; pass the same configuration
object to whichever helpers the application needs.

### `NearAiCloudOptions`

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey` | `string` | Yes | — | Bearer token for signature and evidence requests. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute HTTPS Cloud API base URL. Credentials, query parameters, and fragments are rejected. |
| `fetch?` | `NearAiCloudFetch` | No | Global `fetch` | Fetch-compatible transport used for these helpers' Cloud API requests. |

`NearAiCloudFetch` accepts `(input: string | URL | Request, init?: RequestInit)`
and returns `Awaitable<Response>`. `Awaitable<T>` is `T | PromiseLike<T>`.

### Functions

| Function | Input | Resolves to | Behavior |
| --- | --- | --- | --- |
| `lookupCompletionSignature(cloud, input)` | `cloud: NearAiCloudOptions`, `input: FetchCompletionSignatureInput` | `CompletionSignatureLookup` | Returns either a signature or a service-provided unavailable state. |
| `fetchCompletionSignature(cloud, input)` | `cloud: NearAiCloudOptions`, `input: FetchCompletionSignatureInput` | `CompletionSignature` | Returns a signature; use `lookupCompletionSignature` when the application needs to handle an unavailable state itself. |
| `fetchModelAttestations(cloud, input)` | `cloud: NearAiCloudOptions`, `input: FetchModelAttestationsInput` | `FetchedModelAttestations` | Creates a fresh client nonce and fetches the Cloud API model-attestation response, optionally filtered by signing algorithm and signing address. Use `findModelAttestationForSignature` to bind that result to a `provider_tee` signature. |
| `fetchModelAttestationForSignature(cloud, input)` | `cloud: NearAiCloudOptions`, `input: FetchModelAttestationForSignatureInput` | `FetchedModelAttestation` | Convenience equivalent of `fetchModelAttestations` followed by `findModelAttestationForSignature`. Requires a `provider_tee` signature and requests evidence for its signer. |
| `fetchGatewayAttestation(cloud, input?)` | `cloud: NearAiCloudOptions`, `input?: FetchGatewayAttestationInput` | `FetchedGatewayAttestation` | Creates a fresh client nonce and fetches gateway evidence. It rejects a mismatched echoed nonce and always requests the gateway TLS fingerprint. |

### Request input types

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `FetchCompletionSignatureInput` | `completionId` | `string` | Yes | Non-empty completion ID. |
|  | `signingAlgo?` | `SigningAlgo` | No | Signing algorithm to request. Omitting it requests the service default, `ecdsa`. |
| `FetchModelAttestationsInput` | `model` | `string` | Yes | Non-empty canonical model ID. |
|  | `signingAlgo?` | `SigningAlgo` | No | Optional signing-algorithm filter. Omit it to use the service default. |
|  | `signingAddress?` | `string` | No | Optional signing-address filter. Supply it when requesting evidence for a `provider_tee` response signature. |
| `FetchModelAttestationForSignatureInput` | `model` | `string` | Yes | Non-empty canonical model ID. |
|  | `signature` | `CompletionSignatureReference` | Yes | Signature kind and signer with `kind: 'provider_tee'`; its signer selects the result. A full `CompletionSignature` can be passed directly. |
| `FetchGatewayAttestationInput` | `signingAlgo?` | `SigningAlgo` | No | Gateway signing algorithm. Omitting it requests `ed25519`; when verifying a gateway response, use its signature's signing algorithm. This does not select a gateway instance. |

### Attestation fetch result types

Every attestation fetch helper generates and sends a fresh 32-byte client nonce,
checks the service's echoed nonce, and returns the client nonce with the raw
evidence. Pass the result's `nonce` to the corresponding attestation verifier.

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `attestations` | `readonly ModelAttestation[]` | Cloud API `model_attestations`. The SDK currently requires exactly one item. |
| `FetchedModelAttestation` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `attestation` | `ModelAttestation` | Model attestation selected for the requested `provider_tee` signer. |
| `FetchedGatewayAttestation` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `attestation` | `GatewayAttestation` | Returned gateway attestation. |

## Model attestation selection

### `findModelAttestationForSignature`

Use this function after `fetchModelAttestations` to select the evidence for a
`provider_tee` signature. It requires exactly one signer match but does not
verify the attestation. `fetchModelAttestationForSignature` is the convenience
form of these two operations.

#### `FindModelAttestationForSignatureInput`

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `attestations` | `readonly ModelAttestation[]` | Yes | Model attestations returned by `fetchModelAttestations`. Exactly one item must match `signature.signer`. |
| `signature` | `CompletionSignatureReference` | Yes | `provider_tee` signature whose signer is used for matching. A full `CompletionSignature` can be passed directly. |

## Verification functions

| Function | Input | Returns | Description |
| --- | --- | --- | --- |
| `verifyModelAttestation(input)` | `VerifyModelAttestationInput` | `Promise<VerifiedModelAttestation>` | Verifies model attestation evidence and optional GPU evidence. |
| `verifyModelResponse(input)` | `VerifyModelResponseInput` | `void` | Verifies the exact completion bytes, a `provider_tee` signature, and the supplied model-attestation signer. |
| `verifyGatewayAttestation(input)` | `VerifyGatewayAttestationInput` | `Promise<VerifiedGatewayAttestation>` | Verifies gateway evidence and binds it to the TLS peer observed for its request. |
| `verifyGatewayResponse(input)` | `VerifyGatewayResponseInput` | `void` | Verifies the exact completion bytes, a `gateway` signature, and the supplied gateway-attestation signer. |

### Attestation verification inputs

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelAttestationInput` | `attestation` | `ModelAttestation` | Yes | Raw model evidence. |
|  | `nonce` | `string` | Yes | Client nonce returned by the matching model-attestation fetch result. It must match the evidence. |
|  | `policy?` | `ModelAttestationPolicy` | No | TCB and GPU evidence requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and NVIDIA verifier overrides. |
| `VerifyGatewayAttestationInput` | `attestation` | `GatewayAttestation` | Yes | Raw gateway evidence. |
|  | `nonce` | `string` | Yes | Client nonce returned by the matching gateway-attestation fetch result. It must match the evidence. |
|  | `peerSpkiFingerprint` | `string` | Yes | 32-byte hexadecimal SHA-256 SPKI fingerprint independently observed for the TLS peer that served the attestation request. |
|  | `policy?` | `AttestationPolicy` | No | TCB requirements. |
|  | `verifiers?` | `AttestationVerifiers` | No | Quote and deployment verifier overrides. |

`peerSpkiFingerprint` must be independently observed by the caller. Do not use
`declaredSpkiFingerprint` from the attestation as this field. The SDK compares
the peer fingerprint with quote-bound evidence.

`verifyGatewayResponse` verifies gateway-service provenance and integrity for
the exact completion bytes. It matches the signature to the signer bound to
verified gateway deployment evidence; it does not establish model execution.

### Response verification inputs

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelResponseInput` | `requestBody` | `Uint8Array` | Yes | Exact bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'provider_tee'`. |
|  | `attestation` | `VerifiedModelAttestation` | Yes | Successful model-attestation result whose signer must match the signature. |
| `VerifyGatewayResponseInput` | `requestBody` | `Uint8Array` | Yes | Exact bytes sent to the completion endpoint. |
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
| `CompletionBytes` | `requestBody` | `Uint8Array` | Exact completion request bytes. |
|  | `responseBody` | `Uint8Array` | Exact completion response bytes. |

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
| `declaredSpkiFingerprint?` | `string \| null` | Optional service-declared SPKI fingerprint; it is not a caller-observed TLS peer. |
| `reportedQuoteData?` | `string` | Optional report-data copy cross-checked against the authenticated quote. |

`AttestationEvidence` contains the fields above. `ModelAttestation` and
`GatewayAttestation` extend it as follows:

| Type | Additional field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `ModelAttestation` | `nvidiaPayload?` | `string \| null` | No | GPU attestation payload. |
| `GatewayAttestation` | `reportedQuoteData` | `string` | Yes | Gateway report-data copy. |

## Policies and verifier callbacks

### Policies

| Type | Field | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `AttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
| `ModelAttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
|  | `gpuEvidence?` | `'if-present' \| 'required'` | `'if-present'` | Whether a model report without GPU evidence is accepted. |

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
| `GatewayTlsBinding` | `{ kind: 'peer'; spkiFingerprint: string }` |
| `GpuEvidenceStatus` | `'not_provided' \| 'verified'` |
| `DeploymentProvenanceStatus` | `'not_checked' \| 'verified'` |
