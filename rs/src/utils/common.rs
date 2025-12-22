use anyhow::Context;
use base64::Engine;
use hex;
use serde::de::DeserializeOwned;

pub fn decode_jwt<T: DeserializeOwned>(jwt: &str) -> anyhow::Result<T> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        anyhow::bail!(
            "invalid JWT format: expected 3 segments separated by '.', got {}",
            parts.len()
        );
    }

    let payload = parts[1];
    let padding = (4 - payload.len() % 4) % 4;
    let padded_payload = format!("{}{}", payload, "=".repeat(padding));

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(padded_payload)
        .context("invalid JWT payload base64")?;

    serde_json::from_slice(&decoded).context("invalid JWT payload JSON")
}

pub fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    let hex_trimmed = hex.trim_start_matches("0x");
    Ok(hex::decode(hex_trimmed)?)
}
