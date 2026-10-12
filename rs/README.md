# nearai-inference-sdk (Rust)

`InferenceClient` provides verified Chat Completions with optional field
end-to-end encryption (E2EE), OHTTP, streaming, and explicit response verification.
It verifies the Gateway and supported model deployments before sending Chat and
retains the exact wire bytes used for completion signatures.

## Quickstart

```toml
[dependencies]
nearai-inference-sdk = "0.1"
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Set `NEARAI_API_KEY` in your environment:

```rust,no_run
use nearai_inference_sdk::{InferenceClient, InferenceClientOptions};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(std::env::var("NEARAI_API_KEY")?),
        e2ee: true,
        ..Default::default()
    })?;
    let completion = client.chat_completions(json!({
        "model": "z-ai/glm-5.3-flash",
        "messages": [{"role": "user", "content": "Hello!"}]
    })).await?;
    let verified = client.verify_response(completion["id"].as_str().unwrap()).await?;
    println!("Verified {:?} response", verified.signature_kind());
    println!("{}", completion["choices"][0]["message"]["content"]);
    Ok(())
}
```

Gateway clients default to Ed25519, Gateway TLS binding enabled, and E2EE/OHTTP
disabled. Enable `e2ee` only for supported NEAR model deployments. Models without
NEAR vLLM attestation use Gateway-only verification; model policies and E2EE
reject that path. Failed metadata or attestation checks never downgrade to it.

Clone a client to share connections, caches, and in-flight verification. Call
`verify(model)` to preverify deployments without sending Chat; it returns the
verified evidence and its original verification timestamp. After every completion,
call `verify_response(id)` before treating its output as verified. See the
[guide](./docs/verification-guide.md#integrated-chat-client) for streaming,
cache lifetimes, deployment policies, and experimental direct endpoints.

## Standalone verification

The standalone APIs verify three distinct kinds of NEAR AI Cloud evidence:

- a Gateway deployment attestation, including its TLS endpoint binding when
  available;
- a model-serving deployment attestation; and
- a completion signature over exact request and response bytes.

Optional image-provenance helpers verify GitHub build attestations against a
caller-selected repository, workflow and source pin. See the
[guide](./docs/verification-guide.md#verify-an-images-build-provenance).

The recommended lifecycle has three stages:

1. Before the request, verify the Gateway deployment and every canonical-model
   deployment candidate returned by the Gateway.
2. Send the chat request and retain its exact request and response bytes.
3. Fetch the completion signature and verify that response receipt against the
   corresponding preflight result.

The Gateway may return zero or multiple model candidates. Reject an empty
preflight, verify every returned candidate, and retain the verified results for
response-receipt selection.

The Gateway and model checks are both useful preflight controls. A completion
signature's `CompletionSignatureKind` only selects the final response-receipt
verifier:

| Kind | Verify with | A successful receipt proves |
| --- | --- | --- |
| `ProviderTee` | `verify_model_response` | The verified model signer signed the exact request and response bytes. |
| `Gateway` | `verify_gateway_response` | The verified Gateway signer signed the exact client-visible request and response bytes. |

The current Gateway interface does not yet provide a cryptographic chain from
a particular model response through a Gateway transformation to the final
response. In particular, preflight Gateway and model attestation candidates do not prove
that they served a particular chat completion. [cloud-api#986](https://github.com/nearai/cloud-api/issues/986)
tracks a provider-signature plus Gateway-receipt design for that complete
chain. Verify both deployments before the request, but do not claim more than
the evidence currently proves.

## Documentation

- [Verification guide](./docs/verification-guide.md) walks through the
  preflight, chat, and response-receipt stages.
- [API reference](./docs/api-reference.md) lists the client, verification
  functions, return values, policies, and callback traits.

## Install

```toml
[dependencies]
nearai-inference-sdk = "0.1"
```

When using standalone verification, retain the exact bytes sent to and received
from the completion endpoint. The integrated client captures these automatically.

Gateway SPKI fingerprint evidence is requested by default. The Rust client
captures the peer certificate for that same HTTPS attestation request. A
runtime without peer-certificate access must use
`GatewayAttestationFetchOptions { include_spki_fingerprint: false, ..Default::default() }`.
That still verifies Gateway deployment evidence, but makes no TLS identity
claim. Model attestation fetches always omit TLS fingerprint evidence because
the Gateway, rather than the client, connects to the model.

## Error handling

Cloud client methods and model-evidence selection return `ApiError`. Local
verification functions return `VerificationError`. Handle each at its own call
site: a client or selection operation never needs to dispatch between the two
error types. Match variants when practical, or use `code()` and `retryable()`
for a stable machine-readable classification; never parse display text. See the
[error-handling section](./docs/verification-guide.md#handle-errors) for
completion-signature failures.

Integrated client methods return `InferenceError`, which wraps `ApiError` or
`VerificationError`. Both `code()` and `retryable()` delegate to the underlying
failure. Transient signature retrieval failures can be retried without replaying
Chat. Verification failures remain failures; the client never automatically
replays inference.
