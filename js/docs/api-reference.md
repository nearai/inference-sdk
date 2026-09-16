# TypeScript SDK API reference

This page describes the attestation, E2EE, and response verification APIs in
`verifiable-ai-sdk`. For integration steps and examples, see the
[verification guide](./verification-guide.md).

## Package entry points

Both entry points export the same verification APIs. Their attestation and
secure clients differ in whether they can bind Gateway evidence to the TLS peer
that returned it.

| Import | Gateway evidence behavior |
| --- | --- |
| `verifiable-ai-sdk` | Generic `AttestationClient` and `SecureClient` use `include_tls_fingerprint=false`, so Gateway verification returns `tlsBinding.kind: 'none'`. Their `includeSpkiFingerprint` option can only be `false`. |
| `verifiable-ai-sdk/node` | Node `AttestationClient` captures the TLS peer for its Gateway-evidence request and requests an SPKI fingerprint by default. Node secure clients additionally pin later model-evidence, Chat, and receipt-signature HTTPS requests to that attested SPKI. Set `gatewayVerification.includeSpkiFingerprint: false` on a secure client, or `includeSpkiFingerprint: false` on `AttestationClient`, to use the no-TLS flow. |

TLS binding requires an HTTPS endpoint. For an HTTP custom endpoint, set
`gatewayVerification.includeSpkiFingerprint: false` on a secure client or
`includeSpkiFingerprint: false` on `AttestationClient`.

Node request pinning checks every later TLS peer. It permits a new HTTPS
connection when that peer presents the attested SPKI; it does not require the
Gateway-attestation socket to be reused.

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `SecureClient` | `new SecureClient(options)` | Chat Completions with deployment verification, E2EE, and response verification. |
| `AttestationClient` | `new AttestationClient(options)` | Fetches Gateway signatures and attestation evidence. |
| `createPinnedTlsFetch` from `verifiable-ai-sdk/node` | `(spkiFingerprint: string) => typeof fetch` | Creates an HTTPS Fetch transport that requires every peer to present an already attested SHA-256 SPKI fingerprint. |
| `verifyModelAttestation` | `(params: VerifyModelAttestationParams) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(params: VerifyModelResponseParams) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(params: VerifyGatewayAttestationParams) => Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence and its TLS binding when the returned attestation includes an SPKI fingerprint. |
| `verifyGatewayResponse` | `(params: VerifyGatewayResponseParams) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `findModelAttestationForSignature` | `(params: FindModelAttestationForSignatureParams) => VerifiedModelAttestation` | Selects the single verified model attestation matching a `provider_tee` signature. |

## `SecureClient`

Provides `chat.completions.create()`, a reusable `fetch` adapter, and
`verifyResponse(id)`. Supports streaming and non-streaming Chat Completions.
See the [guide](./verification-guide.md#e2ee-scope-and-response-handling)
for supported encryption fields and protocols.

### Constructor options

`SecureClientOptions` configures the client.
Supply `apiKey`, `headers`, or both. `apiKey` is the direct-Gateway shortcut;
`headers` supports a proxy or another compatible endpoint.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey?` | `string` | When `headers` is absent | — | Direct-Gateway credential. The SDK sends it as `Authorization: Bearer …` and gives it precedence over an `Authorization` value in `headers`. |
| `headers?` | `HeadersInit` | When `apiKey` is absent | — | Static headers sent to every evidence, signature, and Chat request. Use this for a proxy's bearer token, API key, tenant header, or other authentication scheme. SDK protocol headers override conflicts. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute API base URL without a query or fragment. This may be a compatible proxy endpoint. |
| `attestationCacheTimeToLiveMs?` | `number` | No | `900000` | Reuses a successful verified Gateway/model session for this many milliseconds for the same model. Set `0` to verify every request. |
| `responseCacheTimeToLiveMs?` | `number` | No | `900000` | Retains response bytes and verification results for this many milliseconds after body completion. Independent of the attestation cache. |
| `signingAlgo?` | `SigningAlgo` | No | `'ed25519'` | Selects the evidence, model-key routing, receipt, and E2EE protocol. Set `'ecdsa'` for the legacy secp256k1 ECDH and AES-GCM protocol. |
| `e2ee?` | `boolean` | No | `true` | Enables secure Chat field encryption for the selected algorithm. `false` keeps Gateway/model verification and deployment policy checks, routes a plaintext Chat request to a verified model key, and still supports response verification. |
| `deploymentPolicy?` | `DeploymentPolicy` | No | — | Optional model deployment check. No approval policy is provided by default. Throw to reject. |
| `gatewayVerification?` | `GatewayVerificationOptions` | No | — | Advanced Gateway attestation settings. In the Node entry point, it can also disable direct-Gateway TLS binding. |
| `modelVerification?` | `ModelVerificationOptions` | No | — | Advanced model attestation policy and verifier overrides. |

| Type | Field or signature | Description |
| --- | --- | --- |
| `DeploymentPolicy` | `(params: DeploymentPolicyParams) => Awaitable<void>` | Resolves only for an accepted model deployment. |
| `DeploymentPolicyParams` | `model: string` | Model named by the current Chat request. |
|  | `deployment: MeasuredDeployment` | Authenticated deployment measurements to approve or reject. |
| `GatewayVerificationOptions` | `policy?: AttestationPolicy` | Gateway TCB policy override. |
|  | `verifiers?: AttestationVerifiers` | Gateway quote and deployment verifier overrides. |
|  | `includeSpkiFingerprint?: false` | Generic entry point only. Gateway TLS binding is unavailable, so this may only be `false`. |
| `GatewayVerificationOptions` from `verifiable-ai-sdk/node` | `includeSpkiFingerprint?: boolean` | Defaults to `true`. Set `false` for a proxy or HTTP endpoint, where the observed TLS peer is not the attested Gateway. |
| `ModelVerificationOptions` | `policy?: ModelAttestationPolicy` | Model TCB and GPU-evidence policy override. |
|  | `verifiers?: Omit<ModelAttestationVerifiers, 'deployment'>` | Model quote and NVIDIA verifier overrides. Use `deploymentPolicy` for model deployment checks. |

### Methods and result

| Method or type | Signature or field | Description |
| --- | --- | --- |
| `SecureClient.getBaseUrl()` | `string` | Resolved API base URL used by this client. |
| `SecureClient.fetch(input, init?)` | `Promise<Response>` | Reads the Chat request's `model`, verifies it on a cache miss, then sends the request. With E2EE enabled, encrypts supported fields and returns a decrypted JSON or SSE response. |
| `SecureClient.chat.completions.create(body, options?)` | OpenAI Chat `create` overloads | Ordinary or streaming OpenAI-compatible Chat Completions call. Its required `model` selects the evidence verified for this request. With E2EE enabled, protocol-covered fields are encrypted and other fields are preserved without E2EE transformation. |
| `SecureClient.verifyResponse(completionId)` | `Promise<VerifiedCompletionReceipt>` | Fetches and verifies the signature using the bytes and verified evidence retained for this ID. Repeated calls share the verification result. Unknown or expired IDs reject with `api.completion_not_found`. |
| `VerifiedCompletionReceipt.completionId` | `string` | Completion ID whose signature was verified. |
| `VerifiedCompletionReceipt.signatureKind` | `'provider_tee' \| 'gateway'` | Trust boundary of the verified signature. `provider_tee` uses matching model evidence; `gateway` uses Gateway evidence. |

Consume the returned `Response` or stream before awaiting `verifyResponse(id)`.
Records retain complete request and response bodies until their TTL expires,
including after successful or failed verification. TTL starts at body completion.

## `AttestationClient`

Construct `AttestationClient` once to fetch attestations and response signatures.
It does not send Chat requests or retain their bodies.

The Node `AttestationClient` observes the TLS peer only for its Gateway
attestation request. After `verifyGatewayAttestation` returns an
`attested` TLS binding, pass its `spkiFingerprint` to
`createPinnedTlsFetch` for raw HTTPS requests your application owns. The
Node secure clients apply this automatically to their complete Chat flow.

For one three-stage verification operation, pass the same explicit
`signingAlgo` to both attestation fetches and `fetchCompletionSignature`.
The Gateway's report and signature endpoints have different defaults.

### Constructor

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey?` | `string` | When `headers` is absent | — | Direct-Gateway credential. The SDK sends it as `Authorization: Bearer …` and gives it precedence over an `Authorization` value in `headers`. |
| `headers?` | `HeadersInit` | When `apiKey` is absent | — | Static headers sent to every evidence and signature request. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute HTTP(S) Gateway API base URL without a query or fragment. Include the API path when using a custom endpoint. |

### Methods

| Method | Params | Resolves to | Behavior |
| --- | --- | --- | --- |
| `fetchCompletionSignature(params)` | `FetchCompletionSignatureParams` | `CompletionSignature` | Returns the completion signature. A service-provided unavailable result fails the request with a structured API error. |
| `fetchModelAttestations(params)` | `FetchModelAttestationsParams` | `FetchedModelAttestations` | Creates a fresh client nonce and fetches model deployment evidence, optionally filtered by signing algorithm and signing address. Verify every returned candidate for a deployment check. |
| `fetchGatewayAttestation(params?)` | `FetchGatewayAttestationParams` | `FetchedGatewayAttestation` | Creates a fresh client nonce, fetches Gateway evidence, and rejects a mismatched echoed nonce. Its SPKI behavior depends on the package entry point above. |

### Operation-specific parameter fields

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `FetchCompletionSignatureParams` | `completionId` | `string` | Yes | Completion ID returned by the API response. |
|  | `signingAlgo?` | `SigningAlgo` | No | Signing algorithm to request. Omitting it follows the service default. |
| `FetchModelAttestationsParams` | `model` | `string` | Yes | Canonical model ID. |
|  | `signingAlgo?` | `SigningAlgo` | No | Optional signing-algorithm filter for narrowing the Gateway response. |
|  | `signingAddress?` | `string` | No | Optional signing-address filter for narrowing the Gateway response. It must be hexadecimal: 20 or 32 bytes without `signingAlgo`, or the matching length when an algorithm is selected. Invalid input throws `ApiError` before a request. |
| `FetchGatewayAttestationParams` | `signingAlgo?` | `SigningAlgo` | No | Gateway signing algorithm. Omit to use the service default. Use the same algorithm when fetching a response signature. |
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
|  | `attestations` | `readonly ModelAttestation[]` | Gateway `model_attestations`. The collection may be empty or contain multiple candidates; verify every candidate before a completion. |
| `FetchedGatewayAttestation` | `attestation` | `GatewayAttestation` | Returned Gateway attestation. |
|  | `clientBinding` | `GatewayClientBinding` | Client values associated with this evidence request. Pass it to `verifyGatewayAttestation`. |
| `ModelClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
| `GatewayClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `spkiFingerprint?` | `string` | SHA-256 SPKI fingerprint observed for the HTTPS request that returned this evidence. The Node client supplies it when `includeSpkiFingerprint` is `true`; the generic client does not. |

## Model attestation selection

### `findModelAttestationForSignature`

Use this function after verifying every candidate returned by
`client.fetchModelAttestations`. It selects the one verified result whose
signer matches a `provider_tee` signature. It requires exactly one signer
match and performs no additional cryptographic verification.

#### `FindModelAttestationForSignatureParams`

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `attestations` | `readonly VerifiedModelAttestation[]` | Yes | Successful results from `verifyModelAttestation`. Exactly one item must match `signature.signer`. |
| `signature` | `CompletionSignatureReference` | Yes | `provider_tee` signature whose signer is used for matching. A full `CompletionSignature` can be passed directly. |

## Verification functions

| Function | Params | Returns | Description |
| --- | --- | --- | --- |
| `verifyModelAttestation(params)` | `VerifyModelAttestationParams` | `Promise<VerifiedModelAttestation>` | Verifies model attestation evidence and optional GPU evidence. |
| `verifyModelResponse(params)` | `VerifyModelResponseParams` | `void` | Verifies exact completion body bytes, a `provider_tee` signature, and the supplied model-attestation signer. |
| `verifyGatewayAttestation(params)` | `VerifyGatewayAttestationParams` | `Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence. A returned `attestation.spkiFingerprint` requires and checks `clientBinding.spkiFingerprint`. |
| `verifyGatewayResponse(params)` | `VerifyGatewayResponseParams` | `void` | Verifies exact completion body bytes, a `gateway` signature, and the supplied gateway-attestation signer. |

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
fingerprint by default. An `attested` binding can be passed to
`createPinnedTlsFetch`; a `none` binding cannot pin later HTTPS requests.

`verifyGatewayResponse` verifies gateway-service provenance and integrity for
the exact completion body bytes. It matches the signature to the signer bound to
verified gateway deployment evidence; it does not establish model execution.

### Response verification parameters

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelResponseParams` | `requestBody` | `Uint8Array` | Yes | Exact request body bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact response body bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'provider_tee'`. |
|  | `attestation` | `VerifiedModelAttestation` | Yes | Successful model-attestation result whose signer must match the signature. |
| `VerifyGatewayResponseParams` | `requestBody` | `Uint8Array` | Yes | Exact request body bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact response body bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'gateway'`. |
|  | `attestation` | `VerifiedGatewayAttestation` | Yes | Successful gateway-attestation result whose signer must match the signature. |

Call both attestation verifiers before sending a completion. Later, pass the
matching previously verified attestation selected by `signature.kind` to the
response verifier.
## Completion signatures and evidence

### Signature kinds

`CompletionSignature.kind` selects the response verifier and the previously
verified attestation to use.

| Kind | Signed at | Required verified evidence | A successful response verification establishes |
| --- | --- | --- | --- |
| `provider_tee` | Model-serving TEE | `VerifiedModelAttestation` | A verified model TEE signer signed the exact request and response body bytes. |
| `gateway` | Gateway TEE | `VerifiedGatewayAttestation` | A verified Gateway signer signed the exact client-visible request and response body bytes. It does not establish model execution. |

The Gateway returns a `gateway` signature when it rewrites a response and
the provider signature no longer matches the client-visible bytes.

### Completion signatures

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `signingAlgo` | `SigningAlgo` | Signing algorithm. |
|  | `signingAddress` | `string` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignature` | `kind` | `'provider_tee' \| 'gateway'` | Selects model or Gateway response verification. |
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
|  | `signingPublicKey?` | `string` | No | E2EE model public key supplied by the service. Verification binds an Ed25519 key directly, or derives an ECDSA signing address, from the quote-bound signer before returning it. |
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

The default NVIDIA verifier verifies NRAS's overall JWT signature, issuer,
timestamps, signed nonce, and boolean verdict. Provide `nvidia` to use different
trust roots or another verification service.

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
|  | `signingPublicKey?` | `string` | Quote-bound model key available for E2EE. |
| `VerifiedGatewayAttestation` | `tlsBinding` | `GatewayTlsBinding` | Gateway TLS binding established by the returned quote layout. Its `attested` SPKI can pin later Node HTTPS requests. |

| Alias | Definition |
| --- | --- |
| `GatewayTlsBinding` | `{ kind: 'none' } \| { kind: 'attested'; spkiFingerprint: string }` |
| `GpuEvidenceStatus` | `'not_provided' \| 'verified'` |
| `DeploymentProvenanceStatus` | `'not_checked' \| 'verified'` |
