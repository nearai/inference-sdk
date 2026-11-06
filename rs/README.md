# NEAR AI Inference SDK for Rust

`nearai_inference_sdk` provides Chat Completions, Responses, Messages, and System One
with deployment attestation, response signature verification, and optional encryption.

## Install

Rust stable and Cargo.

```sh
cargo add nearai-inference-sdk serde_json
cargo add tokio --features macros,rt-multi-thread
```

## Send and verify a Chat completion

Set `NEARAI_API_KEY`, then send a request with E2EE enabled:

```sh
export NEARAI_API_KEY='your-api-key'
```

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
    // Verify the completion signature before using the answer.
    let verified = client.verify_response(completion["id"].as_str().unwrap()).await?;
    println!("Verified {:?} response", verified.signature_kind());
    println!("{}", completion["choices"][0]["message"]["content"]);
    Ok(())
}
```

The client uses the NEAR AI Cloud Gateway by default. It verifies the Gateway and
every returned model report before inference. Call `verify_response(id)` to verify
the response signature; consume streaming responses completely first.

Use `chat_completions()` for JSON, or `chat_request()` and `send()` for streaming.
The [runnable project](../examples/example-rs) includes the Tokio setup.

## Configuration

| Feature | Default |
| --- | --- |
| Gateway and supported model attestation | Enabled |
| Signing algorithm | Ed25519; ECDSA also supported |
| E2EE for supported Chat models | Disabled; enable with `e2ee: true` |
| OHTTP for Chat, Responses, and Messages | Disabled; enable with `ohttp: true`; requires Ed25519 |

Call `client.verify(model).await?` to verify a deployment before sending a prompt.
Use deployment and image provenance policies to restrict accepted deployments.
For models without model attestation, use Gateway-only verification with E2EE
disabled and no model attestation policy or deployment checks configured.

## Documentation

- [Verification guide](./docs/verification-guide.md): streaming, official SDK integration,
  encryption, deployment policies, and standalone verification.
- [API reference](./docs/api-reference.md): options, methods, and result fields.
- [Runnable examples](../examples/README.md#rust-setup): Gateway and Direct workflows.
- [Development checks](../TESTING.md#validation) and [live E2E tests](../e2e/README.md).
