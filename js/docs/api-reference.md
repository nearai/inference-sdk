# TypeScript SDK API reference

This page describes the Cloud request and verification APIs exported by
`verifiable-ai-sdk`. For the three-stage flow—verify Gateway and model
deployments, send a completion, then verify its receipt—see the
[verification guide](./verification-guide.md).

## Package entry points

Both entry points export the same verification functions. Their
`AttestationClient` differs only for Gateway TLS binding.

| Import | Gateway attestation behavior |
| --- | --- |
| `verifiable-ai-sdk` | Generic client. It defaults to `include_tls_fingerprint=false`, so Gateway verification returns `tlsBinding.kind: 'none'`. Its `includeSpkiFingerprint` option can only be `false`. |
| `verifiable-ai-sdk/node` | Node client. It captures the TLS peer for its evidence request and requests an SPKI fingerprint by default. Set `includeSpkiFingerprint: false` to use the generic no-TLS flow. |

TLS binding requires an HTTPS endpoint. For an HTTP custom endpoint, use
`includeSpkiFingerprint: false`.

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `AttestationClient` | `new AttestationClient(options)` | Fetches Cloud API signatures and attestation evidence. |
| `verifyModelAttestation` | `(params: VerifyModelAttestationParams) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(params: VerifyModelResponseParams) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(params: VerifyGatewayAttestationParams) => Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence and its TLS binding when the returned attestation includes an SPKI fingerprint. |
| `verifyGatewayResponse` | `(params: VerifyGatewayResponseParams) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `findModelAttestationForSignature` | `(params: FindModelAttestationForSignatureParams) => ModelAttestation` | Selects the single model attestation matching a `provider_tee` signature. It does not verify evidence. |

## `AttestationClient`

`AttestationClient` owns Cloud API configuration. Construct it once, then use
its methods to retrieve signatures and evidence. It does not send completion
requests or retain their request or response bytes. Its methods, and
`findModelAttestationForSignature`, throw `ApiError`; verification begins only
when an explicit `verify…` function is called. Handle these operations at
separate call sites: the client and selection helpers use `ApiError`, while
explicit `verify…` functions use `VerificationError`.

For one three-stage verification operation, pass the same explicit
`signingAlgo` to both attestation fetches and `fetchCompletionSignature`.
Cloud API's report and signature endpoints have different defaults.

### Constructor

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey` | `string` | Yes | — | Bearer token for signature and evidence requests. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute HTTP(S) Cloud API base URL. Include the API path when using a custom endpoint. |

### Methods

| Method | Params | Resolves to | Behavior |
| --- | --- | --- | --- |
| `fetchCompletionSignature(params)` | `FetchCompletionSignatureParams` | `CompletionSignature` | Returns the completion signature. A service-provided unavailable result fails the request with a structured API error. |
| `fetchModelAttestations(params)` | `FetchModelAttestationsParams` | `FetchedModelAttestations` | Creates a fresh client nonce and fetches model deployment evidence, optionally filtered by signing algorithm and signing address. Verify its sole result for a deployment preflight. |
| `fetchModelAttestationForSignature(params)` | `FetchModelAttestationForSignatureParams` | `FetchedModelAttestation` | Post-completion convenience equivalent of `fetchModelAttestations` followed by `findModelAttestationForSignature`. Requires a `provider_tee` signature and requests evidence for its signer. |
| `fetchGatewayAttestation(params?)` | `FetchGatewayAttestationParams` | `FetchedGatewayAttestation` | Creates a fresh client nonce, fetches Gateway evidence, and rejects a mismatched echoed nonce. Its SPKI behavior depends on the package entry point above. |

### Operation-specific parameter fields

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `FetchCompletionSignatureParams` | `completionId` | `string` | Yes | Completion ID returned by the API response. |
|  | `signingAlgo?` | `SigningAlgo` | No | Signing algorithm to request. Omitting it follows the service default. |
| `FetchModelAttestationsParams` | `model` | `string` | Yes | Canonical model ID. |
|  | `signingAlgo?` | `SigningAlgo` | No | Optional signing-algorithm filter for narrowing the Cloud API response. |
|  | `signingAddress?` | `string` | No | Optional signing-address filter for narrowing the Cloud API response. It must be hexadecimal: 20 or 32 bytes without `signingAlgo`, or the matching length when an algorithm is selected. Invalid input throws `ApiError` before a request. |
| `FetchModelAttestationForSignatureParams` | `model` | `string` | Yes | Canonical model ID. |
|  | `signature` | `CompletionSignatureReference` | Yes | Signature kind and signer with `kind: 'provider_tee'`; its signer selects the result. A full `CompletionSignature` can be passed directly. |
| `FetchGatewayAttestationParams` | `signingAlgo?` | `SigningAlgo` | No | Gateway signing algorithm. Omit it to use the Cloud API default. For a preflight operation that selects an algorithm, use the same value when fetching the completion signature. This does not select a gateway instance. |
| `FetchGatewayAttestationParams` from `verifiable-ai-sdk` | `includeSpkiFingerprint?` | `false` | No | `false`. The generic client defaults to `include_tls_fingerprint=false`. |
| `FetchGatewayAttestationParams` from `verifiable-ai-sdk/node` | `includeSpkiFingerprint?` | `boolean` | No | `true`. Requests `include_tls_fingerprint=true` by default and captures the matching TLS peer fingerprint. Set `false` for the signer-and-nonce quote layout. |

### Attestation fetch result types

Every attestation fetch method generates and sends a fresh 32-byte client nonce
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
|  | `spkiFingerprint?` | `string` | SHA-256 SPKI fingerprint observed for the HTTPS request that returned this evidence. The Node client supplies it when `includeSpkiFingerprint` is `true`; the generic client does not. |

## Model attestation selection

### `findModelAttestationForSignature`

Use this function after `client.fetchModelAttestations` to select evidence for a
`provider_tee` signature. It requires exactly one signer match but does not
verify the attestation. `client.fetchModelAttestationForSignature` is the
convenience form of these two operations. The normal preflight workflow verifies
the fetched model attestation before the completion instead.

#### `FindModelAttestationForSignatureParams`

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `attestations` | `readonly ModelAttestation[]` | Yes | Model attestations returned by `client.fetchModelAttestations`. Exactly one item must match `signature.signer`. |
| `signature` | `CompletionSignatureReference` | Yes | `provider_tee` signature whose signer is used for matching. A full `CompletionSignature` can be passed directly. |

## Verification functions

| Function | Params | Returns | Description |
| --- | --- | --- | --- |
| `verifyModelAttestation(params)` | `VerifyModelAttestationParams` | `Promise<VerifiedModelAttestation>` | Verifies model attestation evidence and optional GPU evidence. |
| `verifyModelResponse(params)` | `VerifyModelResponseParams` | `void` | Verifies the exact completion bytes, a `provider_tee` signature, and the supplied model-attestation signer. |
| `verifyGatewayAttestation(params)` | `VerifyGatewayAttestationParams` | `Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence. A returned `attestation.spkiFingerprint` requires and checks `clientBinding.spkiFingerprint`. |
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
|  | `policy?` | `AttestationPolicy` | No | Accepted TCB statuses. |
|  | `verifiers?` | `AttestationVerifiers` | No | Quote and deployment verifier overrides. |

`clientBinding.nonce` must be the nonce returned with the matching evidence.
The Gateway attestation itself selects the quote layout: a returned
`spkiFingerprint` requires it to match the client-observed peer; no fingerprint
uses the signer-and-nonce layout and returns `tlsBinding.kind: 'none'`. The
generic client defaults to the latter. The Node client requests and captures the
fingerprint by default.

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

Call both attestation verifiers before sending a completion, then pass the
preflight result selected by `signature.kind` to the matching response verifier.
Results are ordinary data, so callers decide when raw evidence must be verified
again after storage, transfer, or reconstruction in another language.

## Completion receipts and raw evidence

### Receipt verifier dispatch

`CompletionSignature.kind` is Cloud API's explicit response-receipt
discriminant. It selects the response verifier after both Gateway and model
deployments have been verified; it is not a choice between two deployment
verification workflows.

| Kind | Signed at | Required verified evidence | A successful response verification establishes |
| --- | --- | --- | --- |
| `provider_tee` | Model-serving TEE | `VerifiedModelAttestation` | A verified model TEE signer signed the exact request and response bytes. |
| `gateway` | NEAR AI Cloud Gateway TEE | `VerifiedGatewayAttestation` | A verified Gateway signer signed the exact client-visible request and response bytes. It does not establish model execution. |

Cloud API can return `gateway` when it rewrites the client-visible response,
because a byte-exact provider signature would no longer match those bytes. A
`gateway` receipt does not cryptographically link the final bytes to an
upstream model response. The missing paired provider signature and Gateway
receipt are tracked in [cloud-api#986](https://github.com/nearai/cloud-api/issues/986).

### Completion signatures

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `signingAlgo` | `SigningAlgo` | Signing algorithm. |
|  | `signingAddress` | `string` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignature` | `kind` | `'provider_tee' \| 'gateway'` | Explicit Cloud API receipt kind that selects the matching preflight result and response verifier. |
|  | `signedText` | `string` | Text covered by the signature. |
|  | `signature` | `string` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
|  | `signer` | `SigningIdentity` | Signing identity that must match verified evidence. |
| `CompletionSignatureReference` | `kind` | `'provider_tee' \| 'gateway'` | Signature kind. `findModelAttestationForSignature` accepts only `provider_tee`. |
|  | `signer` | `SigningIdentity` | Signing identity used when selecting evidence. |

`CompletionSignatureKind` is the union `'provider_tee' | 'gateway'`.
`SigningAlgo` is the union `'ecdsa' | 'ed25519'`.

### Attestation evidence

`AttestationEventLog` is `string | readonly unknown[]`.

| Field | Type | Description |
| --- | --- | --- |
| `nonce` | `string` | Nonce echoed by the service. The client method validates it against, and separately returns, its client nonce. |
| `signer` | `SigningIdentity` | Advertised signing identity. |
| `intelQuote` | `string` | Intel TDX quote. |
| `eventLog` | `AttestationEventLog` | Input used to replay RTMR3 measurements. |
| `appCompose` | `string` | Measured compose configuration text. |

`AttestationEvidence` contains the fields above. `ModelAttestation` and
`GatewayAttestation` extend it as follows:

| Type | Additional field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `ModelAttestation` | `reportedQuoteData?` | `string` | No | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidiaPayload?` | `string` | No | GPU attestation payload. |
| `GatewayAttestation` | `spkiFingerprint?` | `string` | No | Gateway-reported TLS SPKI fingerprint. When present, it must match the client-observed fingerprint before verification returns an attested TLS binding. |
|  | `reportedQuoteData` | `string` | Yes | Gateway report-data copy. |

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

`Awaitable<T>` is `T | PromiseLike<T>`, so a callback may return its result
directly or asynchronously.

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
| `VerifiedModelAttestation` | `gpuEvidence` | `GpuEvidenceStatus` | GPU evidence result. Cloud model verification does not establish a client-to-model TLS binding. |
| `VerifiedGatewayAttestation` | `tlsBinding` | `GatewayTlsBinding` | Gateway TLS binding established by the returned quote layout. |

| Alias | Definition |
| --- | --- |
| `GatewayTlsBinding` | `{ kind: 'none' } \| { kind: 'attested'; spkiFingerprint: string }` |
| `GpuEvidenceStatus` | `'not_provided' \| 'verified'` |
| `DeploymentProvenanceStatus` | `'not_checked' \| 'verified'` |
