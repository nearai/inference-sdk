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
| `@nearai/inference-sdk/node` | Gateway attestation clients request SPKI evidence and capture the attestation request's TLS peer by default. `InferenceClient` pins later requests to that observed key and verifies it against Gateway attestation before sending Chat. Disable this through `gatewayVerification.includeSpkiFingerprint` or `includeSpkiFingerprint` on `AttestationClient.fetchGatewayAttestation()`. |

TLS binding requires an HTTPS endpoint. For an HTTP custom endpoint, set
the relevant `includeSpkiFingerprint` option to `false`.

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `InferenceClient` | `new InferenceClient(options)` | Chat Completions, Responses, Messages, and System One with deployment and response verification; optional Chat E2EE. |
| `AttestationClient` | `new AttestationClient(options)` | Fetches model metadata, Gateway signatures, and attestation evidence. |
| `DirectInferenceClient` | `new DirectInferenceClient(options)` | Experimental Chat and response verification through a model endpoint. |
| `DirectAttestationClient` | `new DirectAttestationClient(options)` | Fetches attestations and signatures from a direct model endpoint. |
| `prepareE2eeChatRequest` | `(params: PrepareE2eeChatRequestParams) => Promise<PreparedE2eeChatRequest>` | Encrypts a Chat request to a model public key and returns its matching response decryptor. |
| `verifyOhttpKeyConfig` | `(params: VerifyOhttpKeyConfigParams) => Uint8Array` | Authenticates an OHTTP key configuration against a verified Ed25519 signer. |
| `createOhttpFetch` | `(params: CreateOhttpFetchParams) => typeof fetch` | Encapsulates requests using an authenticated OHTTP configuration and returns decrypted inner responses. |
| `createPinnedTlsFetch` from `@nearai/inference-sdk/node` | `(spkiFingerprints: string \| readonly string[]) => typeof fetch` | Pins each HTTPS connection to one of the supplied, already verified SHA-256 SPKI fingerprints. Requires a nonempty set; certificate-chain and hostname checks still run. |
| `verifyModelAttestation` | `(params: VerifyModelAttestationParams) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(params: VerifyModelResponseParams) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(params: VerifyGatewayAttestationParams) => Promise<VerifiedGatewayAttestation>` | Verifies Gateway evidence and its TLS binding when the returned attestation includes an SPKI fingerprint. |
| `verifyGatewayResponse` | `(params: VerifyGatewayResponseParams) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `verifyDirectModelAttestation` | `(params: VerifyDirectModelAttestationParams) => Promise<VerifiedDirectModelAttestation>` | Verifies one direct model attestation, including its quote-authenticated SPKI when present. |
| `verifyDirectModelAttestations` | `(params: VerifyDirectModelAttestationsParams) => Promise<VerifiedDirectModelAttestations>` | Verifies all supplied model attestations and checks the serving attestation's observed TLS binding when SPKI evidence is supplied. |
| `verifyDirectModelResponse` | `(params: VerifyDirectModelResponseParams) => readonly VerifiedDirectModelAttestation[]` | Verifies exact completion bytes and returns the verified attestations sharing its model signer. |
| `findModelAttestationsForSignature` | `(params: FindModelAttestationsForSignatureParams) => readonly VerifiedModelAttestation[]` | Returns all verified reports matching a `provider_tee` signer. |
| `findModelAttestationForSignature` | `(params: FindModelAttestationForSignatureParams) => VerifiedModelAttestation` | Deprecated unique-match helper; rejects multiple matches. |
| `fetchImageProvenance` | `(params: FetchImageProvenanceParams) => Promise<readonly string[]>` | Fetches serialized Sigstore bundles from GitHub. |
| `verifyImageProvenance` | `(params: VerifyImageProvenanceParams) => Promise<VerifiedImageProvenance>` | Verifies image build provenance against caller-owned policy. |
| `verifyDeploymentImageProvenance` | `(params: VerifyDeploymentImageProvenanceParams) => Promise<void>` | Verifies images listed in the quote-bound `docker_compose_file`. |
| `verifyComposeManagerDeploymentImageProvenance` | `(params: VerifyComposeManagerDeploymentImageProvenanceParams) => Promise<void>` | Verifies image builds selected from Compose Manager's authenticated action log and recorded compose file. |

## `InferenceClient`

Provides Chat Completions, Responses, Messages, System One, a reusable `fetch`
transport, and `verifyResponse(id)`. The client verifies the Gateway and every
returned model report before inference.

Models without NEAR model attestation use Gateway-only (Incognito) verification.
E2EE and model deployment policies require model attestation.

See [Messages API](./verification-guide.md#messages-api) and
[Responses API](./verification-guide.md#responses-api) for Gateway receipt
semantics, streaming, and supported privacy options.

### Constructor options

`InferenceClientOptions` configures the client. Set `apiKey` or `headers` for
authentication; all other options have the defaults below.

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey?` | `string` | No | — | Bearer credential for model reports, metadata, signature, and inference requests; overrides `headers.Authorization`. |
| `headers?` | `HeadersInit` | No | — | Additional request headers; use `apiKey` for bearer authentication. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute API base URL without a query or fragment. This may be a compatible proxy endpoint. |
| `attestationCacheTimeToLiveMs?` | `number` | No | `3600000` | Deployment verification cache duration; `0` verifies each request. |
| `responseCacheTimeToLiveMs?` | `number` | No | `3600000` | Response retention after body completion; `0` disables retention. |
| `signingAlgo?` | `SigningAlgo` | No | `'ed25519'` | Algorithm for attestation, E2EE, and response signatures. OHTTP requires Ed25519. |
| `e2ee?` | `boolean` | No | `false` | Encrypt supported Chat fields to a verified model key. |
| `ohttp?` | `boolean` | No | `false` | Encrypt Chat, Responses, and Messages HTTP exchanges to the Gateway; requires Ed25519. |
| `deploymentPolicy?` | `DeploymentPolicy` | No | — | Model-aware deployment check. Throw to reject a deployment. |
| `gatewayVerification?` | `GatewayVerificationOptions` | No | — | Advanced Gateway attestation settings. In the Node entry point, it can also disable direct-Gateway TLS binding. |
| `modelVerification?` | `ModelVerificationOptions` | No | — | Model attestation policy and verifier configuration. |

| Type | Field or signature | Description |
| --- | --- | --- |
| `DeploymentPolicy` | `(params: DeploymentPolicyParams) => Awaitable<void>` | Resolves only for an accepted model deployment. |
| `DeploymentPolicyParams` | `model: string` | Model passed to `verify(model)` or named by the current inference request. |
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
| `InferenceClient.verify(model: string)` | `Promise<AttestationVerificationResult>` | Verifies Gateway and model deployments before inference. |
| `InferenceClient.fetch(input, init?)` | `Promise<Response>` | Verified HTTP transport for Chat, Responses, Messages, and System One. |
| `InferenceClient.chat.completions.create(body, options?)` | OpenAI Chat `create` overloads | Creates a Chat completion as JSON or SSE, with optional E2EE. |
| `InferenceClient.messages.create(body, options?)` | Anthropic Messages `create` overloads | Creates a Gateway Message as JSON or SSE with field-level E2EE disabled; optional OHTTP. |
| `InferenceClient.responses.create(body, options?)` | OpenAI Responses `create` overloads | Creates a Gateway Response as JSON or SSE. Requires field-level E2EE disabled; OHTTP is supported. |
| `InferenceClient.systemone.create(request, options?)` | `Promise<SystemOneResult>` | Sends one non-streaming decision request after deployment verification. |
| `InferenceClient.verifyResponse(id)` | `Promise<VerifiedCompletionResult>` | Verifies the response signature using retained request and response bytes. |
| `InferenceClient.clearResponseCache()` | `void` | Discards retained responses and their verification results. |
| `VerifiedCompletionResult.id` | `string` | Chat completion ID, Responses ID, Messages ID, or System One decision ID whose signature was verified. |
| `VerifiedCompletionResult.completionId` | `string` | Deprecated alias of `id`. |
| `VerifiedModelCompletionResult.attestations` | `readonly VerifiedModelAttestation[]` | All verified reports sharing the request's selected model signer. |
| `VerifiedModelCompletionResult.attestation` | `VerifiedModelAttestation` | Deprecated: the report selected for the request key. Use `attestations`. |
| `VerifiedCompletionResult.signatureKind` | `'provider_tee' \| 'gateway'` | `provider_tee` matches the model signer selected before the request. `gateway` uses Gateway evidence and is the only accepted kind for Incognito sessions. |

| `AttestationVerificationResult` field | Type | Description |
| --- | --- | --- |
| `gateway` | `VerifiedGatewayAttestation` | Verified Gateway result and original `report`. |
| `models` | `readonly VerifiedModelAttestation[]` | Every verified model report, in response order. Empty for Gateway-only models. |
| `verifiedAt` | `number` | Unix time in milliseconds when verification completed. |

Consume the response or stream before calling `verifyResponse(id)`. Verify
within `responseCacheTimeToLiveMs`; `0` disables response retention.
Use `clearResponseCache()` to discard retained responses.

### Errors wrapped by official SDKs

Use `getSdkError(error)` to extract an SDK error from an OpenAI or Anthropic
exception. It returns `undefined` if no SDK error is present.

```typescript
import { getSdkError } from '@nearai/inference-sdk/node';

try {
  await client.messages.create({ model, max_tokens: 128, messages });
} catch (error) {
  const sdkError = getSdkError(error);
  if (sdkError !== undefined) console.error(sdkError.failure.code);
  throw error;
}
```

## System One decisions (`InferenceClient.systemone`)

Available on the generic and Node Gateway clients. Use `e2ee: false` and
`ohttp: false` for nonstreaming decision requests.

For `@typesafe-ai/sdk`, pass `client.fetch` to `TypeSafeClient` and disable
request compression and inference retries. Verify its `X-Generation-Id` through
`verifyResponse`. See the [integration guide](./verification-guide.md#use-the-official-typesafe-sdk).

| Method | Parameters | Returns |
| --- | --- | --- |
| `client.systemone.create(request, options?)` | `SystemOneRequest`, optional `SystemOneRequestOptions` | `Promise<SystemOneResult>` |
| `client.verifyResponse(id)` | `result.decisionId` from `X-Generation-Id` | `Promise<VerifiedCompletionResult>` |

| `SystemOneRequest` field | Type | Description |
| --- | --- | --- |
| `model` | `string` | Canonical decision-model ID used to select deployment evidence. |
| `state` | Text, object, or array | Decision context forwarded as JSON. |
| `questions` | Named `SystemOneQuestion` map | Named `noul`, `choice`, `score`, or `box` questions. Names and choice labels may be any string. |
| `assets?` | `Record<string, SystemOneImageAsset>` | Optional named images referenced from the request content. |

| Question `type` | Required `instructions` | `criteria` |
| --- | --- | --- |
| `noul` | Text, object, or array | Optional object with `true` and/or `false` descriptions. |
| `choice` | Text, object, or array | Mapping of labels to descriptions or `null`. |
| `score` | Text, object, or array | Ordered array of level descriptions. |
| `box` | Text, object, or array | Omitted. |

Use `SystemOneRequest<MyQuestions>` and `SystemOneQuestion<MyChoices>` to
annotate application types; `create()` also infers question and choice maps.

| `SystemOneRequestOptions` field | Type | Description |
| --- | --- | --- |
| `headers?` | `HeadersInit` | Additional request headers; use `apiKey` for bearer authentication. |
| `signal?` | `AbortSignal` | Abort signal for the request. |

| `SystemOneResult` field | Type | Description |
| --- | --- | --- |
| `data` | `SystemOneResponse` | Parsed output, unverified until `client.verifyResponse(id)` succeeds. |
| `decisionId` | `string` | Decision ID from `X-Generation-Id`, used to retrieve and verify the signature. |

| `SystemOneResponse` field | Type | Description |
| --- | --- | --- |
| `id?` | `string` | Optional upstream ID; JSON `null` is normalized to `undefined`. |
| `model` | `string` | Reported model ID. |
| `answers` | `Record<string, SystemOneAnswer>` | Named answers. |
| `usage` | `{ input_tokens: number; output_tokens: number }` | Nonnegative integer token counts. |

| Answer `type` | Fields |
| --- | --- |
| `noul` | `noul`: probability in `[0, 1]`. |
| `choice` | `choice`: selected label; `confidence` and `probabilities`: probabilities in `[0, 1]`. |
| `score` | `score`: numeric score; `confidence`, `probabilities`, and `legend`: confidence, level probabilities, and descriptions. |
| `box` | `box`: `SystemOneBoxCoordinates` with finite `top`, `bottom`, `left`, and `right` numbers; optional `confidence`: finite number or `null`. |

Structured content accepts OpenRouter `image_url` JSON parts in state,
instructions, and criteria. An optional JSON `assets` map holds PNG/JPEG images
by reference: `format` (`png`, `jpg`, or `jpeg`), `data_base64` (standard base64),
and optional `type: "image"`. Reference each asset from the request content.
Assets and references pass through unchanged,
including references returned in a Score's `legend`.

See the [native image example](../../examples/example-js/gateway/systemone.ts) and
[run instructions](../../examples/README.md#system-one-images).

See the [guide](./verification-guide.md#system-one-decisions) for a complete call
and the [Node examples](../../examples/README.md#javascript-setup) to run it.

## `DirectInferenceClient`

Connects to a model endpoint and verifies its model attestations. Direct clients
are experimental. The Node client enables attested TLS binding by default.

Supports Chat, Fetch, E2EE, OHTTP, and response verification. Configure it with
`DirectInferenceClientOptions` and an explicit `baseUrl`.

### Constructor options

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `baseUrl` | `string` | Yes | — | Direct model API base URL, including `/v1` where applicable. |
| `apiKey?` | `string` | No | — | Credential accepted by the direct endpoint; overrides an Authorization header. |
| `headers?` | `HeadersInit` | No | — | Additional request headers; use `apiKey` for bearer authentication. |
| `signingAlgo?` | `SigningAlgo` | No | `'ed25519'` | Algorithm for attestation, E2EE, and response signatures. OHTTP requires Ed25519. |
| `e2ee?` | `boolean` | No | `false` | Encrypt supported Chat fields to a verified model key. |
| `ohttp?` | `boolean` | No | `false` | Encrypt Chat requests and responses to the configured Direct endpoint using OHTTP. Requires Ed25519. |
| `attestationCacheTimeToLiveMs?` | `number` | No | `3600000` | Deployment verification cache duration; `0` verifies each request. |
| `responseCacheTimeToLiveMs?` | `number` | No | `3600000` | Response retention after body completion; `0` disables retention. |
| `deploymentPolicy?` | `DeploymentPolicy` | No | — | Model-aware deployment check. Throw to reject a deployment. |
| `includeSpkiFingerprint?` (Node) | `boolean` | No | `true` | Verify and pin Direct TLS. Set `false` for an application proxy or HTTP endpoint. |
| `modelVerification?` | `DirectModelVerificationOptions` | No | — | Model attestation policy and verifier configuration. |

### Methods and response result

| Method | Returns | Description |
| --- | --- | --- |
| `getBaseUrl()` | `string` | Resolved direct API base URL. |
| `verify(model: string)` | `Promise<DirectAttestationVerificationResult>` | Verifies the returned Direct model reports before inference. |
| `chat.completions.create(body, options?)` | OpenAI Chat `create` overloads | Streaming or non-streaming Chat after model verification. |
| `fetch(input, init?)` | `Promise<Response>` | Reusable Chat transport, including for an OpenAI client. |
| `verifyResponse(id)` | `Promise<VerifiedDirectCompletionResult>` | Verifies retained bytes against the model signer selected for the request. |
| `clearResponseCache()` | `void` | Discards retained responses and their verification results. |

| `DirectAttestationVerificationResult` field | Type | Description |
| --- | --- | --- |
| `attestations` | `readonly VerifiedDirectModelAttestation[]` | Every verified report, including reports with a signer not selected for Chat. Each includes its original `report`. |
| `servingAttestation` | `VerifiedDirectModelAttestation` | Verified entry for the endpoint that returned the report. |
| `tlsBinding` | `DirectTlsBinding` | Observed endpoint TLS binding, when enabled. |
| `spkiFingerprints` | `readonly string[]` | Distinct quote-authenticated fingerprints from all returned reports. |
| `verifiedAt` | `number` | Unix time in milliseconds when verification completed. |

| `VerifiedDirectCompletionResult` field | Type | Description |
| --- | --- | --- |
| `id` | `string` | Verified response ID. |
| `completionId` | `string` | Deprecated alias of `id`. |
| `signatureKind` | `'provider_tee'` | Direct responses use model signatures. |
| `signature` | `CompletionSignature` | Verified signature record. |
| `attestations` | `readonly VerifiedDirectModelAttestation[]` | All verified attestations sharing the selected model signer, which must match the response signature. |

## `prepareE2eeChatRequest`

Encrypts a Chat request using a verified model public key and its signing
algorithm. Returns the request and its paired response decryptor.

| Structure | Field | Type | Description |
| --- | --- | --- | --- |
| `PrepareE2eeChatRequestParams` | `request` | `Request` | Required POST request with a JSON Chat Completions body containing a string `model`. |
|  | `modelKey` | `E2eeModelKey` | Required model encryption key. |
| `E2eeModelKey` | `signingAlgo` | `SigningAlgo` | `'ed25519'` or `'ecdsa'`. |
|  | `publicKey` | `string` | Hexadecimal model public key taken from the verified model attestation's `signingPublicKey`. |
| `PreparedE2eeChatRequest` | `request` | `Request` | Request with supported Chat fields encrypted, protocol headers set, and other JSON fields preserved. |
|  | `decryptResponse` | `(response: Response) => Promise<Response>` | Matching JSON or SSE response decryptor. Unsuccessful HTTP responses pass through unchanged. |

Send `request` through your HTTP transport and pass the response to
`decryptResponse`. See the [encryption guide](./verification-guide.md#encrypt-a-raw-chat-request).

## OHTTP helpers

Inference clients perform these steps automatically when `ohttp: true`.
For a manual flow, verify the endpoint's attestation first, authenticate the
advertised configuration with `verifyOhttpKeyConfig`, then pass its returned
bytes to `createOhttpFetch`. The Fetch adapter supports JSON and streaming
responses without changing their inner body bytes.

| Structure | Field | Type | Description |
| --- | --- | --- | --- |
| `VerifyOhttpKeyConfigParams` | `ohttpAttestation` | `OhttpAttestation` | Signed configuration supplied by the attestation endpoint. |
|  | `signer` | `SigningIdentity` | Already verified Gateway signer, or direct serving model signer. Must be Ed25519 and match the configuration's signing key. |
| `CreateOhttpFetchParams` | `keyConfig` | `Uint8Array` | Authenticated raw configuration returned by `verifyOhttpKeyConfig`. |
|  | `baseUrl` | `string` | Endpoint whose origin serves `/ohttp`. Inner requests must have the same origin. |
|  | `fetch?` | `typeof fetch` | Outer transport; defaults to global Fetch. Pass a pinned Fetch adapter to preserve Node TLS binding. |
|  | `forwardedHeaders?` | `readonly string[]` | Additional inner header names to expose on the outer request. Authorization is forwarded automatically. Content and encryption-protocol headers remain inner-only. |
| `OhttpAttestation` | `signingAlgo` | `'ed25519'` | Configuration signature algorithm. |
|  | `signingKey` | `string` | Hexadecimal signing public key. |
|  | `keyConfig` | `string` | Hexadecimal encoded OHTTP key configuration. |
|  | `signature` | `string` | Hexadecimal signature over the raw configuration bytes. |

## `AttestationClient`

Fetches model metadata, attestations, and response signatures.

The Node `AttestationClient` observes the TLS peer only for its Gateway
attestation request. After `verifyGatewayAttestation` returns an
`attested` TLS binding, pass its `spkiFingerprint` to
`createPinnedTlsFetch`, then supply that transport as `fetch` to an evidence
client and use it for raw Chat requests. The Node inference clients apply this
automatically to their complete Chat flow.

For one three-stage verification operation, pass the same explicit
`signingAlgo` to both attestation fetches and `fetchCompletionSignature`.
The Gateway's report and signature endpoints have different defaults.

### Constructor

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey?` | `string` | No | — | Bearer credential for model reports, metadata, and signature requests; overrides `headers.Authorization`. |
| `headers?` | `HeadersInit` | No | — | Additional request headers; use `apiKey` for bearer authentication. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute HTTP(S) Gateway API base URL without a query or fragment. Include the API path when using a custom endpoint. |
| `fetch?` | `typeof globalThis.fetch` | No | Runtime Fetch | Transport for model reports, metadata, and completion signatures. Gateway attestation keeps its default transport and same-request TLS peer capture. |

Credentials are optional for public evidence. Configure `apiKey` or `headers`
when the endpoint requires authentication.

### Methods

| Method | Params | Resolves to | Behavior |
| --- | --- | --- | --- |
| `fetchCompletionSignature(params)` | `FetchCompletionSignatureParams` | `CompletionSignature` | Returns the completion signature. A service-provided unavailable result fails the request with a structured API error. |
| `fetchModelMetadata(model)` | `model: string` | `ModelMetadata` | Returns the provider type and model attestation support. |
| `fetchModelAttestations(params)` | `FetchModelAttestationsParams` | `FetchedModelAttestations` | Creates a fresh client nonce and fetches model attestations matching the requested model and optional signing filters. Verify every returned attestation for a deployment check. |
| `fetchGatewayAttestation(params?)` | `FetchGatewayAttestationParams` | `FetchedGatewayAttestation` | Creates a fresh client nonce, fetches Gateway evidence, and rejects a mismatched echoed nonce. Its SPKI behavior depends on the package entry point above. |

`ModelMetadata` contains `providerType: string` and `attestationSupported: boolean`.
`InferenceClient` uses model verification only when `providerType === 'vllm'`
and `attestationSupported` is `true`.

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

Pass each fetch result's `clientBinding` and attestation together to the
corresponding verifier.

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `clientBinding` | `ModelClientBinding` | Client values associated with this evidence request. Pass it to `verifyModelAttestation`. |
|  | `attestations` | `readonly ModelAttestation[]` | Gateway-returned `model_attestations`. Verify every returned attestation before a completion. |
| `FetchedGatewayAttestation` | `attestation` | `GatewayAttestation` | Returned Gateway attestation. |
|  | `clientBinding` | `GatewayClientBinding` | Client values associated with this evidence request. Pass it to `verifyGatewayAttestation`. |
| `ModelClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
| `GatewayClientBinding` | `nonce` | `string` | Client nonce generated and sent by the SDK. |
|  | `spkiFingerprint?` | `string` | SHA-256 SPKI fingerprint observed for the HTTPS request that returned this evidence. The Node client supplies it when `includeSpkiFingerprint` is `true`; the generic client does not. |

## `DirectAttestationClient`

Fetches model reports and signatures from an experimental Direct endpoint.
The Node client captures the attestation connection's TLS fingerprint by default.

| Constructor field | Type | Required | Description |
| --- | --- | --- | --- |
| `baseUrl` | `string` | Yes | Absolute HTTP(S) provider API base URL, including its version path. |
| `apiKey?` | `string` | No | Endpoint bearer credential; overrides `headers.Authorization`. |
| `headers?` | `HeadersInit` | No | Additional request headers; use `apiKey` for bearer authentication. |
| `fetch?` | `typeof fetch` | No | Signature transport; pass `createPinnedTlsFetch(verified.spkiFingerprints)` after verification. |

| Method | Params | Resolves to | Description |
| --- | --- | --- | --- |
| `fetchModelAttestations(params?)` | `FetchDirectModelAttestationsParams` | `FetchedDirectModelAttestations` | Fetches the serving report and model reports matching the optional signer filters. |
| `fetchCompletionSignature(params)` | `FetchCompletionSignatureParams` | `CompletionSignature` | Fetches a direct model signature, normalized to `kind: 'provider_tee'`. |

| `FetchDirectModelAttestationsParams` field | Type | Default | Description |
| --- | --- | --- | --- |
| `signingAlgo?` | `SigningAlgo` | Service default | Algorithm for attestation, E2EE, and response signatures. OHTTP requires Ed25519. |
| `signingAddress?` | `string` | — | Optional signing-address filter. Omit to fetch the endpoint's unfiltered attestation set. |
| `includeSpkiFingerprint?` (Node) | `boolean` | `true` | Request TLS fingerprints and capture the attestation connection's peer. |

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedDirectModelAttestations` | `servingAttestation` | `DirectModelAttestation` | Attestation returned by the endpoint serving this request; it is also an entry in `attestations`. |
|  | `attestations` | `readonly DirectModelAttestation[]` | Returned model reports, including `servingAttestation`. |
|  | `clientBinding` | `DirectClientBinding` | Client values for the matching verification call. |
|  | `ohttpAttestation?` | `OhttpAttestation` | Signed OHTTP configuration; authenticate against the verified serving signer before use. |
| `DirectClientBinding` | `nonce` | `string` | Fresh client nonce sent with this request. |
|  | `spkiFingerprint?` | `string` | TLS peer fingerprint captured by the Node client for this attestation request. |
| `DirectModelAttestations` | `servingAttestation` | `DirectModelAttestation` | Attestation returned by the endpoint serving this request; it is also an entry in `attestations`. |
|  | `attestations` | `readonly DirectModelAttestation[]` | Returned model reports, including `servingAttestation`. |
|  | `ohttpAttestation?` | `OhttpAttestation` | Signed OHTTP configuration for the serving endpoint. |
| `DirectModelAttestation` | Base fields | `ModelAttestation` | Quote, nonce, signer, measurements, and available GPU evidence. |
|  | `modelName` | `string` | Endpoint-reported model name. |
|  | `instanceId?` | `string` | Instance metadata when supplied by the endpoint. |
|  | `spkiFingerprint?` | `string` | Reported TLS SPKI; must be authenticated by quote verification before use. |

## Direct verification functions

| Parameter type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyDirectModelAttestationsParams` | `servingAttestation` | `DirectModelAttestation` | Yes | Serving report; its contents must match an entry in `attestations`. |
|  | `attestations` | `readonly DirectModelAttestation[]` | Yes | Returned model reports, including `servingAttestation`. |
|  | `clientBinding` | `DirectClientBinding` | Yes | Nonce and observed TLS peer fingerprint from the matching attestation request. |
|  | `policy?` | `ModelAttestationPolicy` | No | Accepted TCB statuses and GPU-evidence requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and GPU verifier overrides. |
| `VerifyDirectModelAttestationParams` | `attestation` | `DirectModelAttestation` | Yes | One direct model attestation. |
|  | `clientBinding` | `ModelClientBinding` | Yes | Client nonce; this operation does not compare an observed TLS peer. |
|  | `policy?` | `ModelAttestationPolicy` | No | TCB and GPU requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and GPU verifier overrides. |
| `VerifyDirectModelResponseParams` | `requestBody` | `Uint8Array` | Yes | Exact request bytes sent. |
|  | `responseBody` | `Uint8Array` | Yes | Exact response bytes received, before E2EE decryption if applicable. |
|  | `signature` | `CompletionSignature` | Yes | Direct model signature with `kind: 'provider_tee'`. |
|  | `attestations` | `readonly VerifiedDirectModelAttestation[]` | Yes | All verified reports returned by the endpoint. |

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `VerifiedDirectModelAttestations` | `servingAttestation` | `VerifiedDirectModelAttestation` | Verified serving attestation from the returned set. |
|  | `attestations` | `readonly VerifiedDirectModelAttestation[]` | All verified reports returned by the endpoint. |
|  | `tlsBinding` | `DirectTlsBinding` | `attested` when the serving quote's SPKI matches the observed peer, or `none` when no TLS evidence is requested. |
|  | `spkiFingerprints` | `readonly string[]` | Distinct quote-authenticated SPKI fingerprints from the verified model attestations. |
| `VerifiedDirectModelAttestation` | Base fields | `VerifiedModelAttestation` | Verified quote, signer, measurements, and GPU result. |
|  | `report` | `DirectModelAttestation` | Original direct report retained for inspection. |
|  | `modelName` / `instanceId?` | `string` | Endpoint-reported model and instance metadata. |
|  | `spkiFingerprint?` | `string` | Quote-authenticated TLS public-key fingerprint. |

`verifyDirectModelAttestations` verifies every returned attestation and compares
the serving attestation with the observed TLS peer when SPKI evidence is supplied.
The browser client requests reports without TLS fingerprints; the Node client
requests and verifies them by default.

## Model attestation selection

### `findModelAttestationsForSignature`

Use this function after verifying every candidate returned by
`client.fetchModelAttestations`. It returns all verified reports whose signer
matches a `provider_tee` signature, preserving their order and individual evidence.
No match is an error. This is selection only; verify the signature with
`verifyModelResponse`.

The deprecated singular `findModelAttestationForSignature` retains its strict
unique-match contract and rejects multiple matches.

#### `FindModelAttestationsForSignatureParams`

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `attestations` | `readonly VerifiedModelAttestation[]` | Yes | Successful results from `verifyModelAttestation`. At least one item must match `signature.signer`. |
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

Verifies required container images from measured `appCompose` against their
GitHub build policies. Use in a deployment callback. Returns `Promise<void>`.

| `VerifyDeploymentImageProvenanceParams` field | Type | Required | Description |
| --- | --- | --- | --- |
| `appCompose` | `string` | Yes | Measurement-bound deployment configuration. |
| `imagePolicies` | `Readonly<Record<string, ImageProvenancePolicy>>` | Yes | Nonempty map from container image repository to required GitHub build identity. |
| `githubToken` | `string` | No | GitHub token for direct requests; ignored when `githubApiUrl` is set. |
| `githubApiUrl` | `string` | No | GitHub API base URL (default: `https://api.github.com`). For frontends without a token, use a [backend endpoint](verification-guide.md#github-api-access). |

Each configured image repository is required. Compose image references must
include a literal SHA-256 digest, for example `repository:tag@sha256:...`.

### `verifyComposeManagerDeploymentImageProvenance`

Verifies the recorded Compose file and selected container images, including the
Compose Manager startup image, against the supplied policies. Use in a model
deployment callback. Returns `Promise<void>`.

| `VerifyComposeManagerDeploymentImageProvenanceParams` field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `deployment` | `MeasuredDeployment` | Yes | — | Verified deployment with authenticated `composeManager` actions. |
| `imagePolicies` | `Readonly<Record<string, ImageProvenancePolicy>>` | Yes | — | Nonempty map of required image repositories and approved build identities. |
| `composeManagerImagePolicy` | `ImageProvenancePolicy & { imageRepository: string }` | Yes | — | Required image repository and build identity for the Compose Manager startup image. |
| `composeRepository` | `string` | No | `nearai/cvm-compose-files` | GitHub repository holding the recorded compose file. |
| `composeFile` | `string` | No | Latest `compose_up` | Restricts selection to the latest action for this exact file path. |
| `githubToken` | `string` | No | — | GitHub token for direct requests; ignored when `githubApiUrl` is set. |
| `githubApiUrl` | `string` | No | — | GitHub API base URL (default: `https://api.github.com`). For frontends without a token, use a [backend endpoint](verification-guide.md#github-api-access). |

See the [model image guide](./verification-guide.md#model-images-deployed-by-compose-manager)
for a complete example.

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `ComposeManagerAttestation` | `actions` | `readonly ComposeManagerAction[]` | Raw signed action fields, retaining wire names and unknown string/string-array fields. |
|  | `actionsHash` | `string` | Reported SHA-256 of canonical action JSON. |
|  | `nonce` | `string` | Echoed challenge. |
|  | `intelQuote` | `string` | TDX quote binding the action hash and nonce. |
|  | `eventLog` | `AttestationEventLog` | Event log to replay against RTMR3. |
|  | `reportedQuoteData?` | `string` | Optional copy checked against verified quote report data. |
| `VerifiedComposeManagerAttestation` | `actions` | `readonly ComposeManagerAction[]` | Quote-authenticated action log. |
|  | `tcbStatus` | `TcbStatus` | Accepted manager quote status. |
|  | `advisoryIds` | `readonly string[]` | Manager quote advisory IDs. |
|  | `runtimeMeasurements` | `RuntimeMeasurements` | Measurements derived from its verified event log. |

Authenticated Compose Manager evidence is available as `deployment.composeManager`.

### `fetchImageProvenance`

Fetches image provenance as serialized Sigstore bundles for `verifyImageProvenance`.

| `FetchImageProvenanceParams` field | Type | Required | Description |
| --- | --- | --- | --- |
| `repository` | `string` | Yes | GitHub `owner/repo` publishing the proofs. |
| `digest` | `string` | Yes | Image manifest digest in `sha256:<64 hex characters>` form. |
| `githubToken` | `string` | No | GitHub token for direct requests; ignored when `githubApiUrl` is set. |
| `githubApiUrl` | `string` | No | GitHub API base URL (default: `https://api.github.com`). For frontends without a token, use a [backend endpoint](verification-guide.md#github-api-access). |

For a custom GitHub endpoint, see [GitHub API access](verification-guide.md#github-api-access).

### `verifyImageProvenance`

Verifies supplied Sigstore bundles against a digest and build policy. Both
deployment helpers call this after selecting images and fetching their proofs.

Supports GitHub Actions SLSA v1 and v0.2 provenance. The build policy selects
the repository and workflow, with optional source ref and commit pins.

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
| `signerIdentity` | `string` | No | Source workflow at its authenticated source ref | Exact certificate SAN URI of a reusable signing workflow, including its ref or SHA. |
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
| `gateway` | Gateway TEE | `VerifiedGatewayAttestation` | A verified Gateway signer signed the exact client-visible request and response body bytes. |

### Completion signatures

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `signingAlgo` | `SigningAlgo` | Signing algorithm. |
|  | `signingAddress` | `string` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignature` | `kind` | `'provider_tee' \| 'gateway'` | Selects model or Gateway response verification. |
|  | `signedText` | `string` | Text covered by the signature. |
|  | `signature` | `string` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
|  | `signer` | `SigningIdentity` | Signing identity that must match verified evidence. |
| `CompletionSignatureReference` | `kind` | `'provider_tee' \| 'gateway'` | Signature kind. Model-attestation selection helpers accept only `provider_tee`. |
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
|  | `composeManagerAttestation?` | `ComposeManagerAttestation` | No | Deployment-control evidence, authenticated during model verification when present. |
|  | `signingPublicKey?` | `string` | No | E2EE model public key supplied by the service. Verification binds an Ed25519 key directly, or derives an ECDSA signing address, from the quote-bound signer before returning it. |
|  | `nvidiaPayload?` | `string` | No | GPU attestation payload. |
| `GatewayAttestation` | `spkiFingerprint?` | `string` | No | Gateway-reported TLS SPKI fingerprint. When present, it must match the client-observed fingerprint before verification returns an attested TLS binding. |
|  | `reportedQuoteData` | `string` | Yes | Gateway report-data copy. |
|  | `ohttpAttestation?` | `OhttpAttestation` | No | Signed OHTTP configuration. Authenticate separately with `verifyOhttpKeyConfig` and the verified Gateway signer before use. |

## Configurable verification services

Both factories return callbacks for the existing `verifiers` parameter. They
retain the built-in verification checks and accept custom service or proxy URLs.
PCCS and NRAS default to NEAR AI's proxies in browsers and the official services
in Node.js. NVIDIA signing keys use the official JWKS URL in both runtimes.

| Function | Parameter type | Returns |
| --- | --- | --- |
| `createTdxQuoteVerifier(params?)` | `CreateTdxQuoteVerifierParams` | `TdxQuoteVerifier` |
| `createGpuEvidenceVerifier(params?)` | `CreateGpuEvidenceVerifierParams` | `GpuEvidenceVerifier` |

| Parameter type | Field | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `CreateTdxQuoteVerifierParams` | `pccsUrl?` | `string` | NEAR AI proxy (browser); Intel PCS (Node.js) | PCCS base URL. DCAP constructs SGX and TDX collateral paths below this base. |
| `CreateGpuEvidenceVerifierParams` | `nrasUrl?` | `string` | NEAR AI proxy (browser); NVIDIA NRAS (Node.js) | Complete GPU evidence POST URL. |
|  | `jwksUrl?` | `string` | `https://nras.attestation.nvidia.com/.well-known/jwks.json` | Full URL for the signing-key GET. Must be a trusted source of NVIDIA keys. |

See [service URL configuration](./verification-guide.md#configure-attestation-service-urls)
for default URLs and custom configuration.

## Policies and verifier callbacks

### Policies

| Type | Field | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `AttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate', 'TDRelaunchAdvised']` | TCB statuses accepted by verification. |
| `ModelAttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate', 'TDRelaunchAdvised']` | TCB statuses accepted by verification. |
|  | `gpuEvidence?` | `'if-present' \| 'required'` | `'if-present'` | Whether a model report without GPU evidence is accepted. |

`TcbStatus` is one of `UpToDate`, `SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`, `TDRelaunchAdvised`,
`TDRelaunchAdvisedConfigurationNeeded`, `Revoked`, or `Unknown`.

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

Use `gpuEvidence` to configure a custom GPU verifier.

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
|  | `readonly composeManager?` | `VerifiedComposeManagerAttestation` | Optional authenticated model deployment-control evidence. |
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
| `VerifiedModelAttestation` | `gpuEvidence` | `GpuEvidenceStatus` | GPU evidence verification status. |
|  | `signingPublicKey?` | `string` | Quote-bound model key available for E2EE. |
|  | `report` | `ModelAttestation` | Original input report retained for inspection, separate from the verified conclusions. |
| `VerifiedGatewayAttestation` | `tlsBinding` | `GatewayTlsBinding` | Gateway TLS binding established by the returned quote layout. Its `attested` SPKI can pin later Node HTTPS requests. |
|  | `report` | `GatewayAttestation` | Original input report retained for inspection, separate from the verified conclusions. |

| Alias | Definition |
| --- | --- |
| `GatewayTlsBinding` | `{ kind: 'none' } \| { kind: 'attested'; spkiFingerprint: string }` |
| `GpuEvidenceStatus` | `'not_provided' \| 'verified'` |
| `DeploymentProvenanceStatus` | `'not_checked' \| 'verified'` |
