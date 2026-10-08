# Rust verification guide

Use this SDK to verify NEAR AI Cloud deployments before requesting inference,
then verify the receipt returned for a particular completion. Use `InferenceClient`
for integrated verified Chat, or retain exact bytes yourself when using the
standalone verification functions.

## Integrated Chat client

The [README quickstart](../README.md#quickstart) sends encrypted Chat and verifies
its response. `InferenceClient::new(api_key)` uses defaults; `with_options` accepts
`InferenceClientOptions` for a custom base URL, headers, encryption, policies,
and cache settings. Only Chat Completions are accepted by `send`.
The client owns authentication and forces `Accept-Encoding: identity` so captured
bytes match the completion receipt, including when adapting an existing request.

`verify(model)` and Chat share a per-model cache and in-flight work. Gateway and
model checks run concurrently after obtaining Gateway TLS evidence. Every returned
model candidate must pass; an empty set for an attestation-capable model is an
error. The model key must match the quote-authenticated signer before it is used
for encryption or routing. Receipt verification requires the selected model
signer or the verified Gateway signer, as indicated by the receipt kind.

The Rust client follows the current JavaScript and Python catalog boundary:
`providerType="vllm"` with `attestationSupported=true` requires model evidence;
other valid catalog entries use Gateway-only verification. E2EE, an explicit
model policy, or a model deployment callback requires model evidence.

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

Add `futures-util = "0.3"` to use `StreamExt`. Raw body chunks are SSE bytes,
not necessarily individual UTF-8 strings or Chat objects. The E2EE transform
preserves SSE control lines and record boundaries, including split CRLF and UTF-8.
Each SSE record is limited to 1 MiB, including in the standalone decryptor.

Consume through HTTP EOF, even after SSE `[DONE]`: trailing bytes and OHTTP final
chunk authentication are part of verification. Dropping a partial stream leaves
no verifiable receipt. Content delivered before `verify_response` succeeds is
not yet signature-verified. `bytes()` and `json()` fully consume the body; use
`json()` only for non-streaming Chat. Unlike an OpenAI SDK transport adapter,
`send(reqwest::Request)` is a Rust transport API; it does not implement a trait
from a third-party OpenAI crate.

### Cache lifetime and limits

Both caches default to 60 minutes. `attestation_cache_ttl = Duration::ZERO`
disables reuse of completed deployment checks. `verify()` results contain Unix
milliseconds in `verified_at`; cache hits preserve that time. Completion records
retain their original evidence even if the deployment cache expires or refreshes.

The response TTL begins after successful full-body consumption. Receipt lookups
and new records prune expired entries; dropping all client clones and responses
releases state. `max_cache_entries` defaults to 1024 for each completed cache
and also bounds concurrent preverification. At capacity, completed caches evict
the oldest entry. `max_response_bytes` defaults to 64 MiB; exceeding it fails
closed. `max_receipt_cache_bytes` defaults to 64 MiB total for retained request
and response bytes, for both Gateway and direct clients. Oldest receipts are
evicted until a new receipt fits; a single receipt exceeding this budget fails
body consumption. Verification shares these byte buffers rather than copying them.
This budget covers cached payloads, not in-flight requests/responses, active
verification holding an evicted receipt, or evidence/metadata overhead.
Set suitable limits for your workload. A missing, expired, evicted, or
incomplete completion yields `api.completion_not_found`. A duplicate retained
completion ID is rejected instead of replacing its original bytes.

### Verification policies and TLS

`GatewayVerificationOptions` and `ModelVerificationOptions` accept TCB policies
and `Arc`-owned quote, GPU, and deployment verifiers. `DeploymentPolicy` adds a
model-aware async callback; it runs after the optional model deployment verifier.
Pass the existing image-provenance helpers through a deployment verifier to
require approved builds. The SDK has no built-in approved-deployment allowlist.

Gateway TLS binding is enabled by default. The client observes the certificate
on the Gateway attestation request and pins subsequent metadata, model evidence,
Chat, and signature requests before any HTTP bytes are written. Normal certificate
chain and hostname validation remain enabled. Redirects are disabled.

For a proxy that terminates TLS, set
`gateway_verification.include_spki_fingerprint = false`. This verifies the
signer-and-nonce report layout without claiming the proxy TLS key is attested.
`create_pinned_tls_client(&fingerprints)` is also available independently for
caller-authenticated pins; it accepts HTTPS only.

### Encryption and OHTTP

Set `e2ee: true` for supported Chat fields. Ed25519 uses X25519, HKDF-SHA256,
and XChaCha20-Poly1305; `SigningAlgo::Ecdsa` selects the legacy secp256k1,
HKDF-SHA256, AES-256-GCM protocol. Every request gets a fresh response key.
Model keys are authenticated against the verified signing identity, including
the Ethereum address derivation for ECDSA. Supported fields match the JavaScript
and Python SDKs: message content and content-part arrays, reasoning, names,
refusals, audio data, tool calls/definitions, function calls, and tool choice.
Response decryption also handles tool results and logprob token/byte fields.
Routing metadata, roles, token counts, and unknown fields remain visible.

`prepare_e2ee_chat_request(request, &verified_model_key)` is the standalone
helper. It returns the encrypted `request` and `decrypt_json` / `decrypt_sse`
methods. It performs no network, attestation, or signature verification. Retain
encrypted wire bytes separately if using standalone receipt verification.

Set `ohttp: true` to encrypt the Chat HTTP exchange to the Gateway. This requires
Ed25519 and a valid Gateway-signed OHTTP key configuration. E2EE is independent.
The implementation uses chunked OHTTP and known/indeterminate-length BHTTP
responses, authenticates the final chunk, and rejects truncated or inconsistent
framing. Evidence and signature requests remain ordinary HTTPS. Authorization
and configured custom headers are forwarded on the outer `/ohttp` request;
content and field-encryption headers remain inside it.

`verify_ohttp_key_config` authenticates raw configuration bytes against a verified
signer. `create_ohttp_client` wraps a caller-supplied reqwest client and an
already-authenticated configuration. The wrapper limits requests to its configured
origin; supply a client with redirects disabled (or a pinned client).

### Experimental direct endpoints

`DirectInferenceClient::new(base_url, api_key)` enables E2EE by default. Its
`verify(model)` returns the complete verified report set, serving report, TLS
binding, and verification timestamp. `with_options` accepts
`DirectInferenceClientOptions`, which also defaults E2EE on. Set `e2ee: false`
explicitly to disable encryption.

Direct clients verify every supplied instance, require the serving report to be
in that set, and retain the selected signer group for receipt verification.
OHTTP is bound to the serving signer. `DirectAttestationClient` and the standalone
`verify_direct_model_attestation(s)` / `verify_direct_model_response` functions
support manual flows. Model names and instance IDs are endpoint metadata, not
quote-authenticated model identity claims.

Direct TLS fingerprint fetching remains disabled pending complete fleet coverage
([cloud-api#1087](https://github.com/nearai/cloud-api/issues/1087)). Normal HTTPS
validation still applies. Independently routed direct requests may reach different
instances; use Gateway clients for production.

### Existing Rust callers

Existing fetch and standalone verification methods remain available. Struct
literals for `ModelAttestation` and `VerifiedModelAttestation` now need
`signing_public_key: None` if no key was supplied. `FetchedGatewayAttestation`
adds `ohttp_attestation: None` for responses without OHTTP evidence. These are
source changes for callers constructing those types directly. New error/resource
enum variants also require updates to exhaustive matches.

## Recommended flow

Treat deployment verification and response verification as separate stages.

| Stage | SDK calls | What it establishes |
| --- | --- | --- |
| Verify deployments | `fetch_gateway_attestation` → `verify_gateway_attestation`; `fetch_model_attestations` → `verify_model_attestation` | The Gateway and every returned model deployment satisfy their quote, policy, measurement, and signer checks; Gateway verification includes TLS peer binding by default. |
| Send chat | Your HTTP client | A request naming the canonical model ID used during preflight. Retain the exact request and response bytes. |
| Verify the completion receipt | `fetch_completion_signature` → response verifier selected by `signature.kind` | The exact bytes were signed by the corresponding verified signer. |

Complete both deployment checks before sending chat. The Gateway may return zero
or more model-attestation candidates: reject an empty preflight and verify every
returned candidate. Retain their verified results for the final stage rather
than fetching new attestations after the completion.
Use a canonical model ID and send `x-no-aliasing: true` with the completion
request so the preflight model and request name the same deployment.

## Verify Gateway and model deployments

This example explicitly selects `SigningAlgo::Ecdsa` for all evidence and
signature requests. Pass the same explicit algorithm to both attestation
fetches and the completion-signature fetch: the Gateway's report and signature
endpoints have different defaults. The APIs also accept `None` for individual
calls, but omitting the algorithm is not suitable for this three-stage flow.

```rust,no_run
use nearai_inference_sdk::{
    verify_gateway_attestation, verify_model_attestation, AttestationClient,
    GatewayAttestationFetchOptions, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation,
};

const MODEL: &str = "z-ai/glm-5.3-flash";

async fn verify_deployments(
    client: &AttestationClient,
) -> Result<
    (
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

    let fetched_models = client
        .fetch_model_attestations(MODEL, Some(SigningAlgo::Ecdsa), None)
        .await?;
    if fetched_models.attestations.is_empty() {
        return Err(std::io::Error::other("Gateway returned no model attestations").into());
    }

    let mut verified = Vec::with_capacity(fetched_models.attestations.len());
    for attestation in &fetched_models.attestations {
        verified.push(
            verify_model_attestation(
                attestation,
                &fetched_models.client_binding,
                None,
                Default::default(),
            )
            .await?,
        );
    }

    Ok((
        verified_gateway,
        verified,
    ))
}
```

Gateway fetches request a TLS SPKI fingerprint by default. The Rust client
captures the certificate peer for that same HTTPS evidence request, and
`verify_gateway_attestation` verifies the quote-bound fingerprint against it.
If the runtime cannot expose the TLS peer certificate, set
`include_spki_fingerprint: false` before fetching. That verifies the Gateway
quote's signer-and-nonce layout but makes no TLS identity claim.

Model fetches always request `include_tls_fingerprint=false`: the Gateway
connects to the model on the client's behalf, so a client cannot make a direct
model TLS binding.

## Send chat

After both preflight checks succeed, send the completion with the canonical
model ID and retain the original bytes. For streaming responses, retain the
original SSE bytes, including framing; do not parse and serialize them again.

## Verify the completion receipt

Fetch the completion signature after the chat request completes. The only part
of this stage that depends on `signature.kind` is the response verifier:

```rust,no_run
use nearai_inference_sdk::{
    find_model_attestation_for_signature, verify_gateway_response,
    verify_model_response, AttestationClient, CompletionSignature,
    CompletionSignatureKind, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation,
};

async fn verify_completion_receipt(
    client: &AttestationClient,
    completion_id: &str,
    request_body: &[u8],
    response_body: &[u8],
    gateway: &VerifiedGatewayAttestation,
    models: &[VerifiedModelAttestation],
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = client
        .fetch_completion_signature(completion_id, Some(SigningAlgo::Ecdsa))
        .await?;

    match signature.kind {
        CompletionSignatureKind::ProviderTee => {
            let model = find_model_attestation_for_signature(models, &signature)?;
            verify_model_response(request_body, response_body, &signature, model)?;
        }
        CompletionSignatureKind::Gateway => {
            verify_gateway_response(request_body, response_body, &signature, gateway)?;
        }
    }
    Ok(())
}
```

`ProviderTee` proves that one preflight-verified model signer signed the exact
request and response bytes. Use `find_model_attestation_for_signature` to
require exactly one verified result for that signer. `Gateway` proves that the preflight-verified
Gateway signer signed the exact client-visible bytes. It is not a choice
between doing model verification and Gateway verification: both were completed
before chat. The kind only determines which signer issued this completion's
receipt.

## Evidence currently available

The preflight attestations and receipt answer complementary questions:

| Evidence | It proves | It does not prove |
| --- | --- | --- |
| Verified Gateway attestation | A Gateway deployment met the configured quote, policy, and optional TLS binding checks. | That this Gateway processed a particular completion. |
| Verified model attestation | A model-serving deployment met the configured quote, policy, signer, and GPU-evidence checks. | That this model produced a particular completion. |
| `ProviderTee` receipt | The verified model signer signed these exact bytes. | Gateway deployment or TLS provenance. |
| `Gateway` receipt | The verified Gateway signer signed these exact client-visible bytes. | That an attested model produced those bytes. |

The Gateway currently returns one response signature, not a cryptographically
linked provider signature and Gateway receipt. As a result, independently
verified preflight evidence plus one current receipt does not prove a complete
model → Gateway → final-response chain for a particular inference.
[cloud-api#986](https://github.com/nearai/cloud-api/issues/986) tracks the
planned evidence model for that chain. Do not infer it from matching model
names, timestamps, signing algorithms, or the signature kind.

## Policy and trust roots

The default policy accepts `TcbStatus::UpToDate` and `TcbStatus::OutOfDate`.
Model GPU evidence is verified when supplied; reports without it are accepted
by default. Set `ModelAttestationPolicy { gpu_evidence:
GpuEvidenceRequirement::Required, ..Default::default() }` when GPU evidence is
mandatory.

`AttestationVerifiers` and `ModelAttestationVerifiers` accept caller-owned
TDX quote, deployment, and—for models—GPU evidence verifiers. A supplied
verifier must return `Ok` only for evidence it accepts. The built-in Intel
verifier retrieves DCAP collateral from PCCS. The default NVIDIA verifier submits
evidence to NRAS, then verifies the overall JWT's ES384 signature against NVIDIA's
JWKS, issuer, expiration, not-before and issued-at times, and signed `eat_nonce`.
The overall verdict must be `true`; detached per-device claims are not consumed.
See [NVIDIA's claims reference](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html).

### Use a PCCS or NRAS proxy

The default Intel collateral base URL is
`https://api.trustedservices.intel.com`; the default NVIDIA
submission URL is `https://nras.attestation.nvidia.com/v3/attest/gpu`, with keys
fetched from `https://nras.attestation.nvidia.com/.well-known/jwks.json`. To route
these requests through your own services, construct the built-in verifiers
with custom URLs and pass them through the existing verifier options:

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
    let tdx_quote = DefaultTdxQuoteVerifier::new("https://attestation.example.com/intel");
    let gpu_evidence = NrasGpuEvidenceVerifier::new(
        "https://attestation.example.com/nvidia/v3/attest/gpu",
    )
    .with_jwks_url("https://attestation.example.com/nvidia/.well-known/jwks.json");
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
`None` to use its official default service.

The Intel URL is a PCCS-compatible base, not an endpoint that returns a verdict.
The `dcap-qvl` adapter appends `/sgx/certification/v4/...` and
`/tdx/certification/v4/...` beneath this base; a supplied certification-v4
suffix is normalized automatically. Preserve Intel's JSON bodies and
URL-encoded issuer-chain headers. The proxy's SGX `rootcacrl` endpoint must
return the CRL as hex text, while `pckcrl?encoding=der` returns DER bytes.
If `rootcacrl` is unavailable, the adapter may fetch the root CRL directly
from its certificate distribution URL.

The NVIDIA URL is the complete POST endpoint. It receives the original JSON
payload and must return NVIDIA's signed NRAS response. The JWKS URL is a separate
GET endpoint and defaults to NVIDIA's official URL when `with_jwks_url` is omitted.
Use only a trusted JWKS proxy: its keys authenticate the signed verdict. The SDK
still requires issuer `https://nras.attestation.nvidia.com`, an ES384 signature,
valid timestamps, the matching signed nonce, and a true overall verdict.
A malformed payload nonce is rejected before submission. Model verification also
checks that nonce against the client challenge before calling any GPU verifier,
including overrides.

## Verify an image's build provenance

Image provenance is optional. Use a digest from a verified deployment's
`app_compose` and choose the GitHub repository and workflow your application
trusts. Do not treat a compose variable's default image as the resolved image
when its value may be overridden.

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

The verifier accepts a bundle only after its Sigstore signature, certificate,
transparency-log evidence, artifact digest and signed SLSA source identity pass.
The SLSA source repository, ref and commit must match the certificate's
authenticated source claims, even without optional ref/commit pins.
`policy.commit` must then match that same source commit.
It tries every supplied bundle until one satisfies the policy. Fetching uses
GitHub's public API; supply an optional GitHub token for authenticated rate
limits. It is not a Gateway API key.

For a cross-repository reusable signing workflow, call
`verify_image_provenance_with_signer_identity` instead and pass its exact
certificate SAN URI, for example
`https://github.com/example/build-workflows/.github/workflows/attest.yml@refs/tags/v1`.
Keep `repository`, `workflow`, `git_ref` and `commit` in `policy` pointed at the
caller/source build, not the reusable workflow. The signer URI may end in a
branch/tag ref or commit SHA and is matched exactly. The verified result's
`git_ref` and `commit` describe the source; `certificate_identity` describes
the signer. Fetching still uses the source repository.

Verification uses `sigstore-verify`'s embedded Sigstore public-good trust-root
snapshot, without a runtime trust-root download. Keep the dependency updated
when Sigstore rotates trust material. This verifies build provenance, not
reproducibility, all deployment images, or the software currently serving a
model. Attestation verification does not call these helpers automatically.

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

Populate the nonempty map with container image repository keys and your own
GitHub build policies, then pass this verifier through
`AttestationVerifiers.deployment` or `ModelAttestationVerifiers.deployment`.
The SDK checks the quote and Compose measurement binding before calling it.
Every configured repository is required, and every matching reference must
include a SHA-256 digest (a tag alongside the digest is allowed). Unlisted
literal images are ignored; any unresolved `$` image reference is rejected,
including defaults. This checks only images in the measured Compose, not model
runtime images loaded later by a launcher or another service.

## Handle errors

Cloud client methods and evidence selection return `Result<T, ApiError>`.
That includes client configuration and input errors, such as an invalid custom
base URL, an API key that cannot be used in an HTTP header, or a non-provider
signature passed to model-evidence selection. These helpers retrieve or select
evidence; they do not verify it. Attestation and response verification
functions return `VerificationError` directly. Keep the boundaries separate:
client and selection code only handles `ApiError`, while explicit verification
code only handles `VerificationError`.

At either boundary, match the relevant error enum variant when practical. Its
`code()` provides a stable machine-readable code, and enum fields contain
code-specific diagnostic details. Display text is for people and must not be
parsed. `retryable()` means a new attempt at the failed external operation may
succeed. It does not mean that re-verifying the same evidence will succeed or
that an inference request should be replayed.

`AttestationClient::fetch_completion_signature` returns a signature or an
`ApiError::CompletionSignatureUnavailable { .. }` with code
`api.completion_signature_unavailable` when the Gateway returns a valid 2xx
unavailable envelope. The error preserves the service's
`provider_error_code` and `provider_message`.

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

A completion-signature HTTP 404 is classified as retryable because it can be
observed before a completion reaches its terminal state. It can also mean an
unknown completion ID, so retry only when the application knows that the
completion may still be finishing. A valid 2xx unavailable envelope is not
retryable: it reports that the Gateway cannot provide a usable signature for that
completion.
