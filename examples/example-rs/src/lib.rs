//! Shared configuration and response handling for the runnable examples.
use nearai_inference_sdk::*;
use serde_json::{json, Value};
use std::{collections::BTreeMap, error::Error, io};
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub const MODEL: &str = "z-ai/glm-5.3-flash";
pub const GATEWAY: &str = "https://cloud-api.near.ai/v1/";
pub const DIRECT: &str = "https://glm-5-3-flash.completions.near.ai/v1/";
// Change to Ecdsa for attestation, encryption, and receipt verification together.
pub const ALGO: SigningAlgo = SigningAlgo::Ed25519;
pub fn api_key() -> Result<String> {
    Ok(std::env::var("NEARAI_API_KEY")?)
}
pub fn body(stream: bool) -> Value {
    json!({"model": MODEL, "messages": [{"role":"user", "content":"Reply with the word ok."}], "max_completion_tokens":1024, "stream":stream})
}
pub fn request(base: &str, key: &str, stream: bool) -> Result<reqwest::Request> {
    Ok(reqwest::Client::new()
        .post(format!("{}chat/completions", base))
        .bearer_auth(key)
        .header("accept-encoding", "identity")
        .header("x-no-aliasing", "true")
        .json(&body(stream))
        .build()?)
}
// These four Gateway build policies match the JS/Python examples. They do not
// approve model runtime images or weights. Add commit pins if your policy needs them.
pub struct GatewayImages;
#[async_trait::async_trait]
impl DeploymentVerifier for GatewayImages {
    async fn verify(
        &self,
        deployment: &MeasuredDeployment,
    ) -> std::result::Result<(), VerificationError> {
        let policies: BTreeMap<_, _> = [
            ("cloud-api", "build.yml"),
            ("cvm-ingress", "build-push.yml"),
            ("dstack-vpc", "build.yml"),
            ("dstack-vpc-client", "build.yml"),
        ]
        .into_iter()
        .map(|(name, workflow)| {
            (
                format!("nearaidev/{name}"),
                ImageProvenancePolicy::new(
                    format!("nearai/{name}"),
                    format!(".github/workflows/{workflow}"),
                ),
            )
        })
        .collect();
        verify_deployment_image_provenance(&deployment.app_compose, &policies, None).await
    }
}
// Called only after full HTTP EOF. Buffering avoids assuming network chunks are
// complete UTF-8 strings or SSE records. Display only after receipt verification.
pub fn completion_id(bytes: &[u8], stream: bool) -> Result<String> {
    if !stream {
        return id(&serde_json::from_slice(bytes)?);
    }
    let events: Vec<_> = std::str::from_utf8(bytes)?
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .collect();
    if events.last().copied() != Some("[DONE]") {
        return Err(io::Error::other("Stream ended before [DONE]").into());
    }
    let mut found = None;
    for event in events
        .into_iter()
        .filter(|s| !s.is_empty() && *s != "[DONE]")
    {
        let value: Value = serde_json::from_str(event)?;
        if value.get("id").is_some() {
            let next = id(&value)?;
            if found.as_ref().is_some_and(|old| old != &next) {
                return Err(io::Error::other("Conflicting completion IDs").into());
            }
            found = Some(next);
        }
    }
    found.ok_or_else(|| io::Error::other("Stream has no completion ID").into())
}
fn id(value: &Value) -> Result<String> {
    value["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("Missing completion ID").into())
}
pub fn display(bytes: &[u8], stream: bool) -> Result<()> {
    if stream {
        println!("{}", std::str::from_utf8(bytes)?);
    } else {
        let value: Value = serde_json::from_slice(bytes)?;
        println!(
            "{}",
            value["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
        );
    }
    Ok(())
}
