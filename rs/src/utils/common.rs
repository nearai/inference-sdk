use crate::Error;
use base64::Engine;
use hex;
use serde_json::Value;
use std::collections::HashMap;

pub fn decode_jwt(jwt: &str) -> Result<HashMap<String, Value>, Error> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        return Err(Error::other("invalid JWT format".to_owned()));
    }

    let payload = parts[1];
    let padding = (4 - payload.len() % 4) % 4;
    let padded_payload = format!("{}{}", payload, "=".repeat(padding));

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(padded_payload)
        .map_err(Error::other)?;

    let json: HashMap<String, Value> = serde_json::from_slice(&decoded).map_err(Error::other)?;

    Ok(json)
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Error> {
    let hex_trimmed = hex.trim_start_matches("0x");
    hex::decode(hex_trimmed).map_err(Error::other)
}
