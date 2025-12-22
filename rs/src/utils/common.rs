use crate::Error;
use base64::Engine;
use hex;
use serde::de::DeserializeOwned;

pub fn decode_jwt<T: DeserializeOwned>(jwt: &str) -> Result<T, Error> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        return Err(Error::other(format!(
            "invalid JWT format: expected 3 segments separated by '.', got {}",
            parts.len()
        )));
    }

    let payload = parts[1];
    let padding = (4 - payload.len() % 4) % 4;
    let padded_payload = format!("{}{}", payload, "=".repeat(padding));

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(padded_payload)
        .map_err(|e| Error::other(format!("invalid JWT payload base64: {}", e)))?;

    serde_json::from_slice(&decoded)
        .map_err(|e| Error::other(format!("invalid JWT payload JSON: {}", e)))
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Error> {
    let hex_trimmed = hex.trim_start_matches("0x");
    hex::decode(hex_trimmed).map_err(Error::other)
}
