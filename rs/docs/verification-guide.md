# Rust verification guide

Use this SDK to verify NEAR AI Cloud deployments before requesting inference,
then verify the receipt returned for a particular completion. Use `InferenceClient`
for integrated verified inference, or retain exact bytes yourself when using the
standalone verification functions.

## Integrated Chat client

The [README example](../README.md#send-and-verify-a-chat-completion) sends
encrypted Chat and verifies its response. Use `InferenceClientOptions` to
configure the endpoint, credentials, encryption, and deployment policies.

The Gateway client verifies Gateway evidence and every returned model report
before inference. Models without model attestation use Gateway-only (Incognito)
verification. E2EE and model deployment policies require model attestation.

### Streaming

Create a streaming Chat request and consume `InferenceResponse.body` to EOF:

```rust,no_run
# async fn example(client: nearai_inference_sdk::InferenceClient) -> Result<(), Box<dyn std::error::Error>> {
use futures_util::StreamExt;
use serde_json::json;
let request = client.chat_request(json!({
    "model": "z-ai/glm-5.3-flash",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
}))?;
let mut response = client.send(request).await?;
if !response.status.is_success() {
    return Err(format!("Chat failed: {}", response.status).into());
}
let mut sse = Vec::new();
while let Some(chunk) = response.body.next().await {
    sse.extend_from_slice(&chunk?);
}
// Parse the completion ID from an SSE data event using your application's SSE parser.
// Then call client.verify_response(&completion_id).await? before displaying buffered content.
# Ok(())
# }
```

Add `futures-util` to use `StreamExt`. Body chunks contain SSE bytes; use an
SSE decoder to extract events, as in the [examples](../../examples/README.md#rust-setup).

Consume the stream to EOF before `verify_response()`. For non-streaming responses,
`bytes()` and `json()` read the full body.

### Cache lifetime

Set `attestation_cache_ttl` to control deployment verification reuse;
`Duration::ZERO` verifies every request. Verify responses before
`response_cache_ttl` expires. Both default to one hour.

### Verification policies and TLS

Use `GatewayVerificationOptions` and `ModelVerificationOptions` for TCB policies
and custom verifiers. Use `DeploymentPolicy` for model-aware deployment checks
and image provenance policies to restrict accepted builds.

Gateway requests use attested TLS pinning by default.

For an application proxy, set `gateway_verification.include_spki_fingerprint`
to `false`. For manual requests, `create_pinned_tls_client()` creates a transport
from verified fingerprints.

### Encryption and OHTTP

E2EE requests use `X-Encryption-Version: 3`, binding the reply public key and
field label through authenticated data. The endpoint must support v3. See the
[wire protocol](https://github.com/nearai/inference-proxy/blob/main/docs/e2ee.md)
for the format and supported fields.

Set `e2ee: true` to encrypt supported Chat fields: message content, reasoning,
audio, tools, and function calls. Response decryption also handles tool results
and logprobs. Both Ed25519 and ECDSA are supported.

`prepare_e2ee_chat_request(request, &verified_model_key)` returns the encrypted
request and `decrypt_json` / `decrypt_sse` helpers. Retain the encrypted request
and response bytes for standalone signature verification.

Set `ohttp: true` to encrypt the HTTP exchange to the Gateway. OHTTP requires
Ed25519 and an endpoint serving `/ohttp`. E2EE and OHTTP can be enabled
independently or together.

For manual OHTTP, authenticate the key configuration with
`verify_ohttp_key_config`, then pass it to `create_ohttp_client`.

### Experimental direct endpoints

`DirectInferenceClient` connects to a model endpoint and verifies every returned
model report. Use `DirectInferenceClientOptions` with `e2ee: true` for encryption.

`verify_response(id)` returns `VerifiedDirectCompletionResult` with all matching
model reports in `attestations`.

For manual workflows, use `DirectAttestationClient` and
`verify_direct_model_attestation(s)` / `verify_direct_model_response`.

Direct clients are experimental. Requests use the verified model TLS fingerprints
by default.

## Verify System One decisions

Create a Gateway client with E2EE and OHTTP disabled. Send structured questions
with `client.systemone_create(&request).await`, then call
`client.verify_response(&result.decision_id).await` before using `result.data.answers`.

The [API reference](./api-reference.md#system-one-decisions) describes request
and result types. To try a complete application, run the
[Rust decision example](../../examples/README.md#rust-setup).

## Messages API

Gateway clients support Messages creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the message `id` after reading a JSON response, or `message_start.message.id`
after consuming the stream. Messages use Gateway receipts.

```rust
let message = client.create_message(serde_json::json!({
    "model": "anthropic/claude-haiku-4-5",
    "max_tokens": 128,
    "messages": [{"role": "user", "content": "Hello"}]
})).await?;
let id = message["id"].as_str().ok_or("missing message ID")?;
client.verify_response(id).await?;
```

For streaming, use `message_request(body)` with `"stream": true`, then `send()`
and consume `response.body` to completion. Set custom Anthropic headers on the
request before sending. See the [example](../../examples/example-rs/src/gateway/messages.rs).

## Responses API

Gateway clients support Responses creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the response `id` after reading a JSON response, or `event.response.id`
after consuming the stream. Responses use Gateway receipts.

```rust
let response = client.create_response(serde_json::json!({
    "model": "z-ai/glm-5.3-flash", "input": "Reply with the word ok.", "store": false
})).await?;
let id = response["id"].as_str().ok_or("missing response ID")?;
let receipt = client.verify_response(id).await?;
```

For SSE, build `response_request(json!({ ... , "stream": true }))`, pass it to
`send`, and consume `InferenceResponse.body` to EOF. It contains original SSE
bytes; an application SSE decoder can read the nested response ID.

## Recommended flow

Treat deployment verification and response verification as separate stages.

| Stage | SDK calls | What it establishes |
| --- | --- | --- |
| Verify deployments | `fetch_gateway_attestation` → `verify_gateway_attestation`; `fetch_model_attestations` → `verify_model_attestation` | The Gateway and every returned model deployment satisfy their quote, policy, measurement, and signer checks; Gateway verification includes TLS peer binding by default. |
| Send chat | Your HTTP client | A request naming the canonical model ID used during preflight. Retain the exact request and response bytes. |
| Verify the completion receipt | `fetch_completion_signature` → response verifier selected by `signature.kind` | The exact bytes were signed by the corresponding verified signer. |

For an attested model, require at least one report and verify every returned
report. Retain these results for response verification.

## Verify Gateway and model deployments

Use the same signing algorithm for attestation and signature requests.
This example uses ECDSA:

```rust,no_run
use nearai_inference_sdk::{
    create_pinned_tls_client, verify_gateway_attestation, verify_model_attestation,
    AttestationClient, GatewayAttestationFetchOptions, GatewayTlsBinding, SigningAlgo,
    VerifiedGatewayAttestation, VerifiedModelAttestation,
};

const MODEL: &str = "z-ai/glm-5.3-flash";

async fn verify_deployments(
    client: AttestationClient,
) -> Result<
    (
        AttestationClient,
        reqwest::Client,
        VerifiedGatewayAttestation,
        Vec<VerifiedModelAttestation>,
    ),
    Box<dyn std::error::Error>,
> {
    let fetched_gateway = client
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(SigningAlgo::Ecdsa),
            ..Default::default()
        })
        .await?;
    let verified_gateway = verify_gateway_attestation(
        &fetched_gateway.attestation,
        &fetched_gateway.client_binding,
        None,
        Default::default(),
    )
    .await?;

    let GatewayTlsBinding::Attested { spki_fingerprint } = &verified_gateway.tls_binding else {
        return Err(std::io::Error::other("Gateway TLS binding is required").into());
    };
    let http = create_pinned_tls_client(std::slice::from_ref(spki_fingerprint))?;
    let client = client.with_http_client(http.clone());
    let fetched_model_attestations = client
        .fetch_model_attestations(MODEL, Some(SigningAlgo::Ecdsa), None)
        .await?;
    if fetched_model_attestations.attestations.is_empty() {
        return Err(std::io::Error::other("Gateway returned no model attestations").into());
    }

    let mut model_attestations = Vec::with_capacity(fetched_model_attestations.attestations.len());
    for attestation in &fetched_model_attestations.attestations {
        model_attestations.push(
            verify_model_attestation(
                attestation,
                &fetched_model_attestations.client_binding,
                None,
                Default::default(),
            )
            .await?,
        );
    }

    Ok((client, http, verified_gateway, model_attestations))
}
```

Use the returned pinned HTTP client for Chat and the returned `AttestationClient`
for signature lookup. Both use the Gateway TLS identity verified during bootstrap.

## Send chat

After both preflight checks succeed, send the completion with the canonical
model ID and retain the original bytes. For streaming responses, retain the
original SSE bytes, including framing; do not parse and serialize them again.

## Verify the completion receipt

Fetch the completion signature after the chat request completes, and choose the
verifier according to `signature.kind`. Retain `selected_model_attestation`, the verified
report used to select the request's routing/encryption public key, for the
model-signature check.

```rust,no_run
use nearai_inference_sdk::{
    verify_gateway_response, verify_model_response, AttestationClient,
    CompletionSignatureKind, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation,
};

async fn verify_completion_response(
    client: &AttestationClient,
    completion_id: &str,
    request_body: &[u8],
    response_body: &[u8],
    gateway: &VerifiedGatewayAttestation,
    selected_model_attestation: &VerifiedModelAttestation,
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = client
        .fetch_completion_signature(completion_id, Some(SigningAlgo::Ecdsa))
        .await?;

    match signature.kind {
        CompletionSignatureKind::ProviderTee => {
            verify_model_response(request_body, response_body, &signature, selected_model_attestation)?;
        }
        CompletionSignatureKind::Gateway => {
            verify_gateway_response(request_body, response_body, &signature, gateway)?;
        }
    }
    Ok(())
}
```

Use `find_model_attestations_for_signature` to obtain all verified reports
sharing the model receipt's signer. Gateway receipts use the verified Gateway.

## Policy and trust roots

The default policy accepts `TcbStatus::UpToDate`, `TcbStatus::OutOfDate`, and
`TcbStatus::TdRelaunchAdvised`.
Model GPU evidence is verified when supplied; reports without it are accepted
by default. Set `ModelAttestationPolicy { gpu_evidence:
GpuEvidenceRequirement::Required, ..Default::default() }` when GPU evidence is
mandatory.

Use `AttestationVerifiers` and `ModelAttestationVerifiers` to configure quote,
deployment, and GPU verification callbacks.

### Configure attestation service URLs

The built-in verifiers use these defaults:

| Service | URL |
| --- | --- |
| PCCS base | `https://api.trustedservices.intel.com` |
| NRAS evidence | `https://nras.attestation.nvidia.com/v3/attest/gpu` |
| NVIDIA signing keys | `https://nras.attestation.nvidia.com/.well-known/jwks.json` |

To use your own services, construct verifiers with custom URLs:

```rust,no_run
use nearai_inference_sdk::{
    verify_model_attestation, DefaultTdxQuoteVerifier, ModelAttestation,
    ModelAttestationVerifiers, ModelClientBinding, NrasGpuEvidenceVerifier,
    VerificationError, VerifiedModelAttestation,
};

async fn verify_with_proxies(
    attestation: &ModelAttestation,
    binding: &ModelClientBinding,
) -> Result<VerifiedModelAttestation, VerificationError> {
    let tdx_quote = DefaultTdxQuoteVerifier::new("https://attestation.example.com/pccs");
    let gpu_evidence = NrasGpuEvidenceVerifier::new(
        "https://attestation.example.com/nras/v3/attest/gpu",
    );
    verify_model_attestation(
        attestation,
        binding,
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            gpu_evidence: Some(&gpu_evidence),
            ..Default::default()
        },
    )
    .await
}
```

Pass the same `tdx_quote` verifier as `AttestationVerifiers { tdx_quote: Some(&tdx_quote),
..Default::default() }` for Gateway verification. Leave either verifier as
`None` to use the defaults above.

DCAP builds the SGX and TDX collateral paths beneath the PCCS base URL.
`NrasGpuEvidenceVerifier` accepts the complete GPU evidence POST URL. Signing
keys come from NVIDIA; call `with_jwks_url` to use another trusted key source.

## Verify an image's build provenance

Use image provenance policies to require a GitHub repository, build workflow,
and optional source version for a container image digest.

```rust,no_run
use nearai_inference_sdk::{
    fetch_image_provenance, verify_image_provenance, ImageProvenancePolicy,
    VerifiedImageProvenance,
};

async fn verify_image(
    digest: &str,
) -> Result<VerifiedImageProvenance, Box<dyn std::error::Error>> {
    let mut policy = ImageProvenancePolicy::new(
        "nearai/compose-manager".to_owned(),
        ".github/workflows/build.yml".to_owned(),
    );
    policy.git_ref = Some("refs/heads/master".to_owned());
    // Set policy.commit as well when your application approves one source commit.
    let bundles = fetch_image_provenance(&policy.repository, digest, None).await?;
    let provenance = verify_image_provenance(&bundles, digest, &policy).await?;
    Ok(provenance)
}
```

Use `git_ref` or `commit` to pin the source version. An optional GitHub token
authenticates provenance retrieval.

For a cross-repository reusable signing workflow, call
`verify_image_provenance_with_signer_identity` instead and pass its exact
certificate SAN URI, for example
`https://github.com/example/build-workflows/.github/workflows/attest.yml@refs/tags/v1`.
Keep `repository`, `workflow`, `git_ref` and `commit` in `policy` pointed at the
caller/source build, not the reusable workflow. The signer URI may end in a
branch/tag ref or commit SHA and is matched exactly. The verified result's
`git_ref` and `commit` describe the source; `certificate_identity` describes
the signer. Fetching still uses the source repository.

To check required images from measured Compose, call
`verify_deployment_image_provenance` in your `DeploymentVerifier`:

```rust,no_run
use std::collections::BTreeMap;
use async_trait::async_trait;
use nearai_inference_sdk::{
    verify_deployment_image_provenance, DeploymentVerifier,
    ImageProvenancePolicy, MeasuredDeployment, VerificationError,
};

struct ApprovedImages(BTreeMap<String, ImageProvenancePolicy>);

#[async_trait]
impl DeploymentVerifier for ApprovedImages {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        verify_deployment_image_provenance(&deployment.app_compose, &self.0, None).await
    }
}
```

Map required container image repositories to their GitHub build policies. Each
matching Compose image must include a literal SHA-256 digest. Pass the callback
through `AttestationVerifiers.deployment` or `ModelAttestationVerifiers.deployment`.

### Model images deployed by Compose Manager

Use a model deployment callback to require the model-serving images and
manager startup image to come from approved builds:

```rust,no_run
use std::collections::BTreeMap;
use async_trait::async_trait;
use nearai_inference_sdk::{
    verify_compose_manager_deployment_image_provenance, DeploymentVerifier,
    ComposeManagerImagePolicy, ImageProvenancePolicy, MeasuredDeployment, VerificationError,
};

struct ModelImages {
    images: BTreeMap<String, ImageProvenancePolicy>,
    manager: ComposeManagerImagePolicy,
}

#[async_trait]
impl DeploymentVerifier for ModelImages {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        verify_compose_manager_deployment_image_provenance(
            deployment, &self.images, &self.manager, Default::default(),
        ).await
    }
}
```

For example, require `nearaidev/vllm-proxy-rs` from `nearai/inference-proxy` and
`nearaidev/compose-manager` from `nearai/compose-manager`, both using
`.github/workflows/build.yml`. Pass the verifier as
`ModelAttestationVerifiers.deployment`. Keep the manager repository and build
identity in `ComposeManagerImagePolicy`, separate from the compose image map.

On Gateway or Direct inference clients, set `model_verification.deployment`.
The policy runs for every model report and requires Compose Manager evidence in
each one. See the [API reference](./api-reference.md#compose-manager-deployment-images)
for file selection, GitHub access, and standalone verification options.

## Handle errors

Cloud retrieval and evidence selection return `ApiError`; verification returns
`VerificationError`. Integrated clients return `InferenceError`.

Match error variants or use `code()` and `retryable()` to handle failures.

```rust,no_run
use nearai_inference_sdk::{ApiError, AttestationClient};

async fn fetch_completion_signature(
    api_key: &str,
    completion_id: &str,
) -> Result<(), ApiError> {
    let client = AttestationClient::new(api_key.to_owned());
    match client.fetch_completion_signature(completion_id, None).await {
        Ok(_signature) => {}
        Err(ApiError::CompletionSignatureUnavailable {
            provider_error_code,
            provider_message,
        }) => {
            eprintln!("no usable signature ({provider_error_code}): {provider_message}");
        }
        Err(error) if error.retryable() => {
            eprintln!("the signature request may succeed on a later attempt");
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
```
