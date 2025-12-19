use hex;
use serde_json::Value;
use std::collections::HashMap;
use base64::Engine;

pub fn decode_jwt(jwt: &str) -> Result<HashMap<String, Value>, String> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let payload = parts[1];
    let padding = (4 - payload.len() % 4) % 4;
    let padded_payload = format!("{}{}", payload, "=".repeat(padding));

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(padded_payload)
        .map_err(|_| "Invalid JWT payload".to_string())?;

    let json: HashMap<String, Value> = serde_json::from_slice(&decoded)
        .map_err(|_| "Invalid JWT payload".to_string())?;

    Ok(json)
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex_trimmed = hex.trim_start_matches("0x");
    hex::decode(hex_trimmed)
        .map_err(|_| "Invalid hex string".to_string())
}

pub fn trim_hex_prefix(hex: &str) -> &str {
    hex.strip_prefix("0x").unwrap_or(hex)
}

