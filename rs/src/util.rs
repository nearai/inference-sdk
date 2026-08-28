use rand::RngCore;
use sha2::{Digest, Sha256, Sha384};

pub const NONCE_BYTES: usize = 32;

pub fn generate_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    let normalized = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    hex::decode(normalized).map_err(|_| ())
}

pub fn normalize_hex(value: &str) -> Result<String, ()> {
    Ok(hex::encode(decode_hex(value)?))
}

pub fn require_hex_length(value: &str, length: usize) -> Result<Vec<u8>, ()> {
    let bytes = decode_hex(value)?;
    if bytes.len() != length {
        return Err(());
    }
    Ok(bytes)
}

pub fn sha256(value: impl AsRef<[u8]>) -> Vec<u8> {
    Sha256::digest(value.as_ref()).to_vec()
}

pub fn sha384(value: impl AsRef<[u8]>) -> Vec<u8> {
    Sha384::digest(value.as_ref()).to_vec()
}

pub fn decode_jwt_payload(jwt: &str) -> Result<serde_json::Value, ()> {
    use base64::Engine;

    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or(())?;
    let payload = parts.next().ok_or(())?;
    let _signature = parts.next().ok_or(())?;
    if parts.next().is_some() {
        return Err(());
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}
