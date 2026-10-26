//! Shared configuration and response handling for the runnable examples.
use futures_util::{Stream, StreamExt};
use nearai_inference_sdk::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    error::Error,
    io::{self, Write},
};
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub const MODEL: &str = "z-ai/glm-5.3-flash";
pub const GATEWAY: &str = "https://cloud-api.near.ai/v1/";
pub const DIRECT: &str = "https://glm-5-3-flash.completions.near.ai/v1/";
pub fn api_key() -> Result<String> {
    Ok(std::env::var("NEARAI_API_KEY")?)
}
pub fn body(stream: bool) -> Value {
    json!({"model": model(), "messages": [{"role":"user", "content":"Reply with the word ok."}], "max_completion_tokens":1024, "stream":stream})
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
// Required Gateway build provenance. Add commit pins for stricter policies.
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
// Called after EOF, so receipt verification covers the complete response.
pub fn completion_id(bytes: &[u8], stream: bool) -> Result<String> {
    if !stream {
        return id(&serde_json::from_slice(bytes)?);
    }
    let mut decoder = EventDecoder::default();
    let values = decoder.push(bytes, true)?;
    if !decoder.done {
        return Err("Stream ended without [DONE]".into());
    }
    let mut found = None;
    for value in values {
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
    if !stream {
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

/// Decode complete records; retain partial UTF-8 and CRLF across network chunks.
#[derive(Default)]
pub struct EventDecoder {
    pending: Vec<u8>,
    pub done: bool,
}
impl EventDecoder {
    pub fn push(&mut self, chunk: &[u8], eof: bool) -> Result<Vec<Value>> {
        self.pending.extend_from_slice(chunk);
        let mut values = Vec::new();
        let (mut start, mut line, mut index) = (0, 0, 0);
        while index < self.pending.len() {
            let byte = self.pending[index];
            if byte != b'\r' && byte != b'\n' {
                index += 1;
                continue;
            }
            if byte == b'\r' && index + 1 == self.pending.len() && !eof {
                break;
            }
            let end = index
                + if byte == b'\r' && self.pending.get(index + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
            if index == line {
                let record = std::str::from_utf8(&self.pending[start..end])?
                    .replace("\r\n", "\n")
                    .replace('\r', "\n");
                let data = record
                    .split('\n')
                    .filter_map(|line| {
                        if line == "data" {
                            Some("")
                        } else {
                            line.strip_prefix("data:")
                                .map(|s| s.strip_prefix(' ').unwrap_or(s))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                if data == "[DONE]" {
                    self.done = true;
                } else if !data.is_empty() {
                    let value: Value = serde_json::from_str(&data)?;
                    if value.get("error").is_some() || value["type"] == "error" {
                        return Err("Stream returned an error".into());
                    }
                    values.push(value);
                }
                start = end;
            }
            line = end;
            index = end;
        }
        self.pending.drain(..start);
        Ok(values)
    }
}
pub fn events(bytes: &[u8]) -> Result<Vec<Value>> {
    EventDecoder::default().push(bytes, true)
}
fn delta(event: &Value) -> &str {
    match event["type"].as_str() {
        Some("content_block_delta") => event["delta"]["text"].as_str(),
        Some("response.output_text.delta") => event["delta"].as_str(),
        _ => event["choices"][0]["delta"]["content"].as_str(),
    }
    .unwrap_or_default()
}
/// Show each text delta immediately and retain the body for ID/receipt handling.
pub async fn read_stream<S, B, E>(mut source: S) -> Result<Vec<u8>>
where
    S: Stream<Item = std::result::Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: Error + 'static,
{
    let mut decoder = EventDecoder::default();
    let mut body = Vec::new();
    while let Some(chunk) = source.next().await {
        let chunk = chunk?;
        body.extend_from_slice(chunk.as_ref());
        for event in decoder.push(chunk.as_ref(), false)? {
            print!("{}", delta(&event));
        }
        io::stdout().flush()?;
    }
    for event in decoder.push(&[], true)? {
        print!("{}", delta(&event));
    }
    println!();
    Ok(body)
}

pub fn model() -> String {
    std::env::var("NEARAI_MODEL").unwrap_or_else(|_| MODEL.into())
}
pub fn gateway() -> String {
    format!(
        "{}/",
        std::env::var("NEARAI_BASE_URL")
            .unwrap_or_else(|_| GATEWAY.into())
            .trim_end_matches('/')
    )
}
pub fn direct() -> String {
    format!(
        "{}/",
        std::env::var("NEARAI_BASE_URL")
            .unwrap_or_else(|_| DIRECT.into())
            .trim_end_matches('/')
    )
}
pub fn algo() -> Result<SigningAlgo> {
    match std::env::var("NEARAI_SIGNING_ALGO")
        .as_deref()
        .unwrap_or("ed25519")
    {
        "ed25519" => Ok(SigningAlgo::Ed25519),
        "ecdsa" => Ok(SigningAlgo::Ecdsa),
        _ => Err("NEARAI_SIGNING_ALGO must be ed25519 or ecdsa".into()),
    }
}
pub fn ohttp() -> bool {
    std::env::var("NEARAI_OHTTP").is_ok_and(|v| v == "true")
}

pub struct ModelImages;
#[async_trait::async_trait]
impl DeploymentVerifier for ModelImages {
    async fn verify(
        &self,
        deployment: &MeasuredDeployment,
    ) -> std::result::Result<(), VerificationError> {
        let policies = BTreeMap::from([(
            "nearaidev/vllm-proxy-rs".into(),
            ImageProvenancePolicy::new(
                "nearai/inference-proxy".into(),
                ".github/workflows/build.yml".into(),
            ),
        )]);
        let manager = ComposeManagerImagePolicy {
            image_repository: "nearaidev/compose-manager".into(),
            build: ImageProvenancePolicy::new(
                "nearai/compose-manager".into(),
                ".github/workflows/build.yml".into(),
            ),
            signer_identity: None,
        };
        verify_compose_manager_deployment_image_provenance(
            deployment,
            &policies,
            &manager,
            Default::default(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_text_before_done_across_byte_boundaries() {
        for separator in ["\n", "\r\n", "\r"] {
            let event = "data: {\"id\":\"chat-1\",\ndata: \"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\n".replace('\n', separator);
            for split in 0..=event.len() {
                let mut decoder = EventDecoder::default();
                let mut values = decoder.push(&event.as_bytes()[..split], false).unwrap();
                values.extend(decoder.push(&event.as_bytes()[split..], false).unwrap());
                // A lone CR needs the next byte to distinguish it from CRLF.
                values.extend(decoder.push(b":", false).unwrap());
                assert_eq!(values.len(), 1);
                assert_eq!(delta(&values[0]), "你好");
                assert!(!decoder.done);
            }
            let body = format!("{event}data: [DONE]{separator}{separator}");
            assert_eq!(completion_id(body.as_bytes(), true).unwrap(), "chat-1");
            assert!(completion_id(event.as_bytes(), true).is_err());
        }
    }

    #[test]
    fn rejects_error_events_and_conflicting_ids() {
        assert!(events(b"data: {\"type\":\"error\"}\n\n").is_err());
        assert!(completion_id(
            b"data: {\"id\":\"one\"}\n\ndata: {\"id\":\"two\"}\n\ndata: [DONE]\n\n",
            true
        )
        .is_err());
    }
}
