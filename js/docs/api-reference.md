# TypeScript SDK API reference

This page describes the attestation, E2EE, and response verification APIs in
`@nearai/inference-sdk`. For integration steps and examples, see the
[verification guide](./verification-guide.md).

## Package entry points

Both entry points export the same verification APIs. Their Gateway clients differ
in whether they can bind endpoint evidence to the TLS peer that returned it.

| Import | TLS behavior |
| --- | --- |
| `@nearai/inference-sdk` | Gateway clients use `include_tls_fingerprint=false`; their `includeSpkiFingerprint` option can only be `false`. The matching attestation verifier returns `tlsBinding.kind: 'none'`. |
| `@nearai/inference-sdk/node` | Gateway attestation clients request SPKI evidence and capture the attestation request's TLS peer by default. `InferenceClient` pins later requests to the verified Gateway key. Disable this through `gatewayVerification.includeSpkiFingerprint` or `includeSpkiFingerprint` on `AttestationClient.fetchGatewayAttestation()`. |

Direct clients in both entry points always request `include_tls_fingerprint=false`.
Direct TLS fingerprint binding and pinning are currently disabled; standard HTTPS
certificate validation still applies.

TLS binding requires an HTTPS endpoint. For an HTTP custom endpoint, set
the relevant `includeSpkiFingerprint` option to `false`.

Node request pinning checks every later TLS peer. It permits a new HTTPS
connection when that peer presents an allowed attested SPKI; it does not require
the attestation socket to be reused.

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `InferenceClient` | `new InferenceClient(options)` | Chat Completions with deployment verification, E2EE, and response verification. |
| `AttestationClient` | `new AttestationClient(options)` | Fetches Gateway signatures and attestation evidence. |
| `DirectInferenceClient` | `new DirectInferenceClient(options)` | Verified Chat and E2EE through a model endpoint, without Gateway verification. |
| `DirectAttestationClient` | `new DirectAttestationClient(options)` | Fetches direct model attestations and signatures. |
| `prepareE2eeChatRequest` | `(params: PrepareE2eeChatRequestParams) => Promise<PreparedE2eeChatRequest>` | Encrypts a Chat request to a model public key and returns its matching response decryptor. |
| `createPinnedTlsFetch` from `@nearai/inference-sdk/node` | `(spkiFingerprints: string \| readonly string[]) => typeof fetch` | Pins each HTTPS connection to one of the supplied, already verified SHA-256 SPKI fingerprints. Requires a nonempty set; certificate-chain and hostname checks still run. |
| `verifyModelAttestation` | `(params: VerifyModelAttestationParams) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(params: VerifyModelResponseParams) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(params: VerifyGatewayAttestationParams) => Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence and its TLS binding when the returned attestation includes an SPKI fingerprint. |
| `verifyGatewayResponse` | `(params: VerifyGatewayResponseParams) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `verifyDirectModelAttestation` | `(params: VerifyDirectModelAttestationParams) => Promise<VerifiedDirectModelAttestation>` | Verifies one direct model attestation, including its quote-authenticated SPKI when present. |
| `verifyDirectModelAttestations` | `(params: VerifyDirectModelAttestationsParams) => Promise<VerifiedDirectModelAttestations>` | Verifies all supplied model attestations and checks the serving attestation's observed TLS binding when SPKI evidence is supplied. |
| `verifyDirectModelResponse` | `(params: VerifyDirectModelResponseParams) => readonly VerifiedDirectModelAttestation[]` | Verifies exact completion bytes and returns the verified attestations sharing its model signer. |
| `findModelAttestationForSignature` | `(params: FindModelAttestationForSignatureParams) => VerifiedModelAttestation` | Selects the single verified model attestation matching a `provider_tee` signature. |
| `fetchImageProvenance` | `(params: FetchImageProvenanceParams) => Promise<readonly string[]>` | Fetches serialized Sigstore bundles from GitHub. |
| `verifyImageProvenance` | `(params: VerifyImageProvenanceParams) => Promise<VerifiedImageProvenance>` | Verifies image build provenance against caller-owned policy. |
| `verifyDeploymentImageProvenance` | `(params: VerifyDeploymentImageProvenanceParams) => Promise<void>` | Verifies required image references in an authenticated deployment configuration. |

## `InferenceClient`

Provides `chat.completions.create()`, a reusable `fetch` adapter, and
`verifyResponse(id)`. Supports streaming and non-streaming Chat Completions.
See the [guide](./verification-guide.md#e2ee-scope-and-response-handling)
for supported encryption fields and protocols.

### Constructor options

`InferenceClientOptions` configures the client.
Supply `apiKey`, `headers`, or both. `apiKey` is the direct-Gateway shortcut;
`headers` supports a proxy or another compatible endpoint.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey?` | `string` | When `headers` is absent | — | Direct-Gateway credential. The SDK sends it as `Authorization: Bearer …` and gives it precedence over an `Authorization` value in `headers`. |
| `headers?` | `HeadersInit` | When `apiKey` is absent | — | Static headers for evidence, signature, and Chat requests. Configured `Authorization` takes precedence over per-request authorization unless `apiKey` is set. Other headers can be overridden per request; SDK protocol headers override conflicts. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute API base URL without a query or fragment. This may be a compatible proxy endpoint. |
| `attestationCacheTimeToLiveMs?` | `number` | No | `3600000` | Reuses a successful verified Gateway/model session for this many milliseconds for the same model. Set `0` to verify every request. |
| `responseCacheTimeToLiveMs?` | `number` | No | `3600000` | Retains response bytes and verification results for this many milliseconds after body completion. Independent of the attestation cache. |
| `signingAlgo?` | `SigningAlgo` | No | `'ed25519'` | Selects the algorithm for attestation, model-key routing, response signatures, and E2EE. Set `'ecdsa'` for the legacy secp256k1 ECDH and AES-GCM protocol. |
| `e2ee?` | `boolean` | No | `true` | Enables secure Chat field encryption for the selected algorithm. `false` keeps Gateway/model verification and deployment policy checks, routes a plaintext Chat request to a verified model key, and still supports response verification. |
| `deploymentPolicy?` | `DeploymentPolicy` | No | — | Optional model-aware deployment check, run after `modelVerification.verifiers.deployment` when both are configured. No approval policy is provided by default. Throw to reject. |
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
| `GatewayVerificationOptions` from `@nearai/inference-sdk/node` | `includeSpkiFingerprint?: boolean` | Defaults to `true`. Set `false` for a proxy or HTTP endpoint, where the observed TLS peer is not the attested Gateway. |
| `ModelVerificationOptions` | `policy?: ModelAttestationPolicy` | Model TCB and GPU-evidence policy override. |
|  | `verifiers?: ModelAttestationVerifiers` | Model quote, deployment, and GPU verifiers. A deployment check must pass before `deploymentPolicy` runs. |

### Methods and result

| Method or type | Signature or field | Description |
| --- | --- | --- |
| `InferenceClient.getBaseUrl()` | `string` | Resolved API base URL used by this client. |
| `InferenceClient.fetch(input, init?)` | `Promise<Response>` | Reads the Chat request's `model`, verifies it on a cache miss, then sends the request. With E2EE enabled, encrypts supported fields and returns a decrypted JSON or SSE response. |
| `InferenceClient.chat.completions.create(body, options?)` | OpenAI Chat `create` overloads | Ordinary or streaming OpenAI-compatible Chat Completions call. Its required `model` selects the evidence verified for this request. With E2EE enabled, protocol-covered fields are encrypted and other fields are preserved without E2EE transformation. |
| `InferenceClient.verifyResponse(completionId)` | `Promise<VerifiedCompletionResult>` | Fetches and verifies the signature using the bytes and verified evidence retained for this ID. Concurrent calls share one operation. A retryable API failure allows a later call to retry; other results remain cached. Unknown or expired IDs reject with `api.completion_not_found`. |
| `VerifiedCompletionResult.completionId` | `string` | Completion ID whose signature was verified. |
| `VerifiedCompletionResult.signatureKind` | `'provider_tee' \| 'gateway'` | Trust boundary of the verified signature. `provider_tee` must match the model signer selected for the request; `gateway` uses Gateway evidence. |

Consume the returned `Response` or stream before awaiting `verifyResponse(id)`.
Records retain complete request and response bodies until their TTL expires,
including after successful or failed verification. TTL starts at body completion.

## `DirectInferenceClient`

Uses the same Chat, Fetch, E2EE, and cache behavior as `InferenceClient`, but
verifies direct model attestations instead of Gateway and Gateway-routed model
evidence. Every attestation in the complete serving set must pass verification
before Chat is sent.
There is no `gatewayVerification` option.

### Constructor options

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `baseUrl` | `string` | Yes | — | Direct model API base URL, including `/v1` where applicable. |
| `apiKey?` | `string` | No | — | Credential accepted by the direct endpoint; overrides an Authorization header. |
| `headers?` | `HeadersInit` | No | — | Authentication or other headers sent to evidence, Chat, and signature requests. |
| `signingAlgo?` | `SigningAlgo` | No | `'ed25519'` | Algorithm used for evidence, model-key routing, E2EE, and signature lookup. |
| `e2ee?` | `boolean` | No | `true` | Encrypts supported Chat fields. `false` preserves model verification and sends plaintext over the selected transport. |
| `attestationCacheTimeToLiveMs?` | `number` | No | `3600000` | Reuses verified model attestations for the same requested model. Set `0` to verify every request. |
| `responseCacheTimeToLiveMs?` | `number` | No | `3600000` | Retains response verification records after body completion. |
| `deploymentPolicy?` | `DeploymentPolicy` | No | — | Additional model-aware deployment check. No approval policy is supplied by default. |
| `modelVerification?` | `DirectModelVerificationOptions` | No | — | Model `policy` and `verifiers`. |

### Methods and response result

| Method | Returns | Description |
| --- | --- | --- |
| `getBaseUrl()` | `string` | Resolved direct API base URL. |
| `chat.completions.create(body, options?)` | OpenAI Chat `create` overloads | Streaming or non-streaming Chat after model verification. |
| `fetch(input, init?)` | `Promise<Response>` | Reusable Chat transport, including for an OpenAI client. |
| `verifyResponse(completionId)` | `Promise<VerifiedDirectCompletionResult>` | Verifies retained bytes against the model signer selected for the request. |

| `VerifiedDirectCompletionResult` field | Type | Description |
| --- | --- | --- |
| `completionId` | `string` | Verified completion ID. |
| `signatureKind` | `'provider_tee'` | Direct responses use model signatures. |
| `signature` | `CompletionSignature` | Verified signature record. |
| `attestations` | `readonly VerifiedDirectModelAttestation[]` | All verified attestations sharing the selected model signer, which must match the response signature. |

## `prepareE2eeChatRequest`

Prepares one encrypted request for an application-owned Fetch transport. It
performs no networking, attestation verification, or completion-signature
verification. Supply the algorithm and public key obtained from model
verification. The helper selects the encryption algorithm from
`modelKey.signingAlgo` and creates a fresh response key pair for each call.

| Structure | Field | Type | Description |
| --- | --- | --- | --- |
| `PrepareE2eeChatRequestParams` | `request` | `Request` | Required POST request with a JSON Chat Completions body containing a string `model`. |
|  | `modelKey` | `E2eeModelKey` | Required model encryption key. |
| `E2eeModelKey` | `signingAlgo` | `SigningAlgo` | `'ed25519'` or `'ecdsa'`. |
|  | `publicKey` | `string` | Hexadecimal model public key taken from the verified model attestation's `signingPublicKey`. |
| `PreparedE2eeChatRequest` | `request` | `Request` | Request with supported Chat fields encrypted, protocol headers set, and other JSON fields preserved. |
|  | `decryptResponse` | `(response: Response) => Promise<Response>` | Matching JSON or SSE response decryptor. Unsuccessful HTTP responses pass through unchanged. |

Send the returned `request` with your chosen transport, then pass its response to
the paired `decryptResponse`. The private response key stays inside that
operation. For Gateway TLS pinning in Node, use `createPinnedTlsFetch` with a
previously verified `attested` Gateway binding. See the
[guide](./verification-guide.md#e2ee-scope-and-response-handling) for field coverage.

## `AttestationClient`

Construct `AttestationClient` once to fetch attestations and response signatures.
It does not send Chat requests or retain their bodies.

The Node `AttestationClient` observes the TLS peer only for its Gateway
attestation request. After `verifyGatewayAttestation` returns an
`attested` TLS binding, pass its `spkiFingerprint` to
`createPinnedTlsFetch` for raw HTTPS requests your application owns. The
Node inference clients apply this automatically to their complete Chat flow.

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
| `fetchModelAttestations(params)` | `FetchModelAttestationsParams` | `FetchedModelAttestations` | Creates a fresh client nonce and fetches the complete serving model-attestation set matching the requested model and optional signing filters. Verify every returned attestation for a deployment check. |
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
| `FetchGatewayAttestationParams` from `@nearai/inference-sdk` | `includeSpkiFingerprint?` | `false` | No | `false`. The generic client defaults to `include_tls_fingerprint=false`. |
| `FetchGatewayAttestationParams` from `@nearai/inference-sdk/node` | `includeSpkiFingerprint?` | `boolean` | No | `true`. Requests `include_tls_fingerprint=true` by default and captures the matching TLS peer fingerprint. Set `false` for the signer-and-nonce quote layout. |

### Attestation fetch result types

Every attestation fetch method generates and sends a fresh 32-byte client nonce
and checks the service's echoed nonce. Each result places its client values in
`clientBinding`. Pair that value with the result's attestation in the matching
attestation verifier.

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `clientBinding` | `ModelClientBinding` | Client values associated with this evidence request. Pass it to `verifyModelAttestation`. |
|  | `attestations` | `readonly ModelAttestation[]` | Gateway `model_attestations` for the complete serving set. Verify every attestation before a completion. |
| `FetchedGatewayAttestation` | `attestation` | `GatewayAttestation` | Returned Gateway attestation. |
|  | `clientBinding` | `GatewayClientBinding` | Client values associated with this evidence request. Pass it to `verifyGatewayAttestation`. |
| `ModelClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
| `GatewayClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `spkiFingerprint?` | `string` | SHA-256 SPKI fingerprint observed for the HTTPS request that returned this evidence. The Node client supplies it when `includeSpkiFingerprint` is `true`; the generic client does not. |

## `DirectAttestationClient`

Fetches `/attestation/report` and `/signature/{id}` relative to a direct model API
base URL. Authentication is optional in the SDK and depends on the endpoint.
Both entry points request `include_tls_fingerprint=false`; this is not configurable.

| Constructor field | Type | Required | Description |
| --- | --- | --- | --- |
| `baseUrl` | `string` | Yes | Absolute HTTP(S) provider API base URL, including its version path. |
| `apiKey?` | `string` | No | Endpoint bearer credential; overrides `headers.Authorization`. |
| `headers?` | `HeadersInit` | No | Additional request headers. |

| Method | Params | Resolves to | Description |
| --- | --- | --- | --- |
| `fetchModelAttestations(params?)` | `FetchDirectModelAttestationsParams` | `FetchedDirectModelAttestations` | Generates a nonce and fetches the serving attestation and complete serving model-attestation set matching the optional signing filters; checks echoed nonces before returning. |
| `fetchCompletionSignature(params)` | `FetchCompletionSignatureParams` | `CompletionSignature` | Fetches a direct model signature, normalized to `kind: 'provider_tee'`. |

| `FetchDirectModelAttestationsParams` field | Type | Default | Description |
| --- | --- | --- | --- |
| `signingAlgo?` | `SigningAlgo` | Service default | Requested signing algorithm. Use the same algorithm for signature lookup. |
| `signingAddress?` | `string` | — | Optional signing-address filter. Omit to fetch the endpoint's unfiltered attestation set. |

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedDirectModelAttestations` | `servingAttestation` | `DirectModelAttestation` | Attestation returned by the endpoint serving this request; it is also an entry in `attestations`. |
|  | `attestations` | `readonly DirectModelAttestation[]` | Complete serving model-attestation set matching the requested filters, including `servingAttestation`. |
|  | `clientBinding` | `DirectClientBinding` | Client values for the matching verification call. |
| `DirectClientBinding` | `nonce` | `string` | Fresh client nonce sent with this request. |
|  | `spkiFingerprint?` | `string` | Optional observed TLS peer SPKI for manually supplied evidence. Direct fetch helpers currently omit it. |
| `DirectModelAttestations` | `servingAttestation` | `DirectModelAttestation` | Attestation returned by the endpoint serving this request; it is also an entry in `attestations`. |
|  | `attestations` | `readonly DirectModelAttestation[]` | Complete serving model-attestation set matching the requested filters, including `servingAttestation`. |
| `DirectModelAttestation` | Base fields | `ModelAttestation` | Quote, nonce, signer, measurements, and available GPU evidence. |
|  | `modelName` | `string` | Metadata, not a model-name claim authenticated by the quote. |
|  | `instanceId?` | `string` | Instance metadata when supplied by the endpoint. |
|  | `spkiFingerprint?` | `string` | Reported TLS SPKI; must be authenticated by quote verification before use. |

## Direct verification functions

| Parameter type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyDirectModelAttestationsParams` | `servingAttestation` | `DirectModelAttestation` | Yes | Serving attestation from the fetch helper; it must be an entry in `attestations`. |
|  | `attestations` | `readonly DirectModelAttestation[]` | Yes | Complete serving model-attestation set from the fetch helper. Every entry is checked. |
|  | `clientBinding` | `DirectClientBinding` | Yes | Nonce from the matching request, plus an observed peer fingerprint when verifying manually supplied TLS-bound evidence. |
|  | `policy?` | `ModelAttestationPolicy` | No | Accepted TCB statuses and GPU-evidence requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and GPU verifier overrides. |
| `VerifyDirectModelAttestationParams` | `attestation` | `DirectModelAttestation` | Yes | One direct model attestation. |
|  | `clientBinding` | `ModelClientBinding` | Yes | Client nonce; this operation does not compare an observed TLS peer. |
|  | `policy?` | `ModelAttestationPolicy` | No | TCB and GPU requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and GPU verifier overrides. |
| `VerifyDirectModelResponseParams` | `requestBody` | `Uint8Array` | Yes | Exact request bytes sent. |
|  | `responseBody` | `Uint8Array` | Yes | Exact response bytes received, before E2EE decryption if applicable. |
|  | `signature` | `CompletionSignature` | Yes | Direct model signature with `kind: 'provider_tee'`. |
|  | `attestations` | `readonly VerifiedDirectModelAttestation[]` | Yes | Previously verified model attestations. All signer matches are returned after byte and signature checks pass. |

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `VerifiedDirectModelAttestations` | `servingAttestation` | `VerifiedDirectModelAttestation` | Verified serving attestation from the complete set. |
|  | `attestations` | `readonly VerifiedDirectModelAttestation[]` | Verified complete serving model-attestation set. |
|  | `tlsBinding` | `GatewayTlsBinding` | `attested` when the serving quote's SPKI matches the observed peer, or `none` when no TLS evidence is requested. |
|  | `spkiFingerprints` | `readonly string[]` | Distinct quote-authenticated SPKI fingerprints from the verified model attestations. |
| `VerifiedDirectModelAttestation` | Base fields | `VerifiedModelAttestation` | Verified quote, signer, measurements, and GPU result. |
|  | `modelName` / `instanceId?` | `string` | Preserved metadata, not additional quote-authenticated claims. |
|  | `spkiFingerprint?` | `string` | Quote-authenticated TLS key; this alone does not claim observation of that instance's TLS peer. |

`verifyDirectModelAttestations` verifies every returned attestation and compares
the serving attestation with the observed TLS peer when SPKI evidence is supplied.
For reports fetched by `DirectAttestationClient`, `tlsBinding.kind` is `'none'`
and `spkiFingerprints` is empty.

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
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and GPU verifier overrides. |
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
## Image build provenance

### `verifyDeploymentImageProvenance`

Parses JSON `appCompose` and its YAML `docker_compose_file`, then fetches and
verifies build proofs for the required images. Returns `Promise<void>`.
Use in a deployment callback: this helper does not authenticate `appCompose`
against a quote itself.

| `VerifyDeploymentImageProvenanceParams` field | Type | Required | Description |
| --- | --- | --- | --- |
| `appCompose` | `string` | Yes | Measurement-bound deployment configuration. |
| `imagePolicies` | `Readonly<Record<string, ImageProvenancePolicy>>` | Yes | Nonempty map from container image repository to required GitHub build identity. |
| `githubToken` | `string` | No | GitHub authentication for fetching proofs. |

Every configured repository must appear in Compose `services`. Each matching
reference must have a literal `sha256:` digest, optionally preceded by a tag.
An optional `docker.io/` prefix is normalized. YAML anchors and merges are
supported; image interpolation is not. Unlisted literal images are ignored.

Throws `VerificationError`: `provenance.deployment_images_invalid` for invalid
configuration, `provenance.image_request_failed` for proof retrieval errors, or
`provenance.image_verification_failed` for rejected proofs. Retrieval errors
preserve the `ApiError` cause and retryability.

### `fetchImageProvenance`

Returns all inline Sigstore bundles as JSON strings. Does not verify them.

| `FetchImageProvenanceParams` field | Type | Required | Description |
| --- | --- | --- | --- |
| `repository` | `string` | Yes | GitHub `owner/repo` publishing the proofs. |
| `digest` | `string` | Yes | Image manifest digest in `sha256:<64 hex characters>` form. |
| `githubToken` | `string` | No | GitHub authentication for API access and rate limits. |

### `verifyImageProvenance`

Accepts a matching GitHub Actions SLSA v1 or v0.2 proof. Sigstore verifies the
certificate, DSSE signature and transparency log before the SDK checks the
artifact digest and signed source. The statement's source commit must match the
certificate's authenticated source SHA, even when `policy.commit` is omitted.
The source repository and ref must also match the certificate's source claims.
No deployment allowlist is provided.
Rekor entries must use the `dsse` format; legacy `intoto` entries are not supported.

| `VerifyImageProvenanceParams` field | Type | Required | Description |
| --- | --- | --- | --- |
| `bundles` | `readonly string[]` | Yes | Serialized bundles from the fetch helper or another source. At least one must satisfy every check. |
| `digest` | `string` | Yes | Expected `sha256:` image manifest digest. |
| `policy` | `ImageProvenancePolicy` | Yes | Required build identity and optional approved version. |

| `ImageProvenancePolicy` field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `repository` | `string` | Yes | — | Expected source/caller repository, `owner/repo`; also used to fetch its attestations. |
| `workflow` | `string` | Yes | — | Caller workflow path within the source repository, such as `.github/workflows/build.yml`. |
| `ref` | `string` | No | Any matching source ref | Restricts the source to one full Git ref, such as `refs/heads/main`. |
| `commit` | `string` | No | Any matching source commit | Restricts the signed source to one full, 40-character Git commit. |
| `signerIdentity` | `string` | No | Source workflow at its authenticated source ref | Exact certificate SAN URI of a reusable signing workflow, including its ref or SHA. Does not change the source policy or fetch repository. |
| `issuer` | `string` | No | `https://token.actions.githubusercontent.com` | Expected certificate OIDC issuer. |

| `VerifiedImageProvenance` field | Type | Description |
| --- | --- | --- |
| `digest` | `string` | Verified image manifest digest, normalized to lowercase. |
| `repository` | `string` | Matched source/caller repository. |
| `workflow` | `string` | Matched caller workflow path. |
| `ref` | `string` | Source Git ref matched between the certificate's source claims and the signed statement. Independent of a reusable signing workflow's ref. |
| `commit` | `string` | Source commit matched against the verified certificate, normalized to lowercase. |
| `certificateIdentity` | `string` | Verified certificate's signing-workflow SAN URI. |
| `issuer` | `string` | Verified OIDC issuer. |
| `predicateType` | `string` | Verified statement's SLSA predicate version. |

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

## Configurable verification services

Both factories return callbacks for the existing `verifiers` parameter. They
retain the built-in verification checks and accept custom service or proxy URLs.
PCCS defaults to Phala in browsers and Intel in Node.js. NVIDIA defaults are
the same in both runtimes.

| Function | Parameter type | Returns |
| --- | --- | --- |
| `createTdxQuoteVerifier(params?)` | `CreateTdxQuoteVerifierParams` | `TdxQuoteVerifier` |
| `createGpuEvidenceVerifier(params?)` | `CreateGpuEvidenceVerifierParams` | `GpuEvidenceVerifier` |

| Parameter type | Field | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `CreateTdxQuoteVerifierParams` | `pccsUrl?` | `string` | Browser: `https://pccs.phala.network`; Node.js: `https://api.trustedservices.intel.com` | Intel PCS or a PCCS-compatible proxy base URL. DCAP constructs the collateral paths below this base. |
| `CreateGpuEvidenceVerifierParams` | `nrasUrl?` | `string` | `https://nras.attestation.nvidia.com/v3/attest/gpu` | Full URL for the GPU evidence POST. |
|  | `jwksUrl?` | `string` | `https://nras.attestation.nvidia.com/.well-known/jwks.json` | Full URL for the signing-key GET. Must be a trusted source of NVIDIA keys. |

The NVIDIA callback verifies the signed JWT nonce against the submitted payload
nonce. `verifyModelAttestation` additionally binds that nonce to
`clientBinding.nonce`; standalone callers must supply fresh evidence themselves.
The expected NVIDIA issuer remains fixed when either URL changes.
See the [proxy setup](./verification-guide.md#connect-through-an-application-proxy)
for routing and response-header requirements.

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
| `AttestationVerifiers` | `tdxQuote?: TdxQuoteVerifier` | Replaces the built-in Intel DCAP quote verifier. |
|  | `deployment?: DeploymentVerifier` | Applies caller-defined deployment acceptance. |
| `ModelAttestationVerifiers` | `tdxQuote?: TdxQuoteVerifier` | Replaces the built-in Intel DCAP quote verifier. |
|  | `deployment?: DeploymentVerifier` | Applies caller-defined deployment acceptance. |
|  | `gpuEvidence?: GpuEvidenceVerifier` | Replaces the default NVIDIA NRAS verifier. |
| `TdxQuoteVerifier` | `(quote: string) => Awaitable<TdxQuoteVerificationResult>` | Authenticates a quote and returns the verified quote fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) => Awaitable<void>` | Resolves only for an accepted deployment. |
| `GpuEvidenceVerifier` | `(payload: string) => Awaitable<void>` | Resolves only for accepted GPU evidence. |

`Awaitable<T>` is `T | PromiseLike<T>`, so a callback may return its result
directly or asynchronously.

The default NVIDIA verifier verifies NRAS's overall JWT signature, issuer,
timestamps, signed nonce, and boolean verdict. Provide `gpuEvidence` to use different
trust roots or another verification service.

### Quote and deployment values

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `TdxQuoteVerificationResult` | `tcbStatus` | `TcbStatus` | Authenticated TCB status. |
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
