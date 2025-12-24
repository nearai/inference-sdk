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

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;

    Ok(serde_json::from_slice(&decoded)?)
}

pub fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    let hex_trimmed = hex.trim_start_matches("0x");
    Ok(hex::decode(hex_trimmed)?)
}
