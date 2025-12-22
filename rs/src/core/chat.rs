use crate::types::attestation_common::SigningAlgo;
use crate::types::attestation_model::ModelAttestation;
use crate::types::chat::{Chat, ChatSignature};
use crate::utils::common::hex_to_bytes;
use crate::utils::errors::Error;

pub fn verify_chat(message: &Chat, signature: &ChatSignature) -> Result<(), Error> {
    verify_chat_hash(
        &signature.text,
        &message.request_body,
        &message.response_body,
    )?;
    verify_chat_signature(signature)?;
    Ok(())
}

pub fn verify_signing_address(
    signature: &ChatSignature,
    attestations: &[ModelAttestation],
) -> Result<(), Error> {
    for attestation in attestations {
        if signature.signing_algo == attestation.signing_algo {
            let sig_addr_bytes = hex_to_bytes(&signature.signing_address)?;
            let att_addr_bytes = hex_to_bytes(&attestation.signing_address)?;

            if sig_addr_bytes == att_addr_bytes {
                return Ok(());
            }
        }
    }

    Err(Error::VerificationError(
        format!(
            "signature signing algorithm/address does not match any model attestations: signing_algo={}, signing_address={}",
            signature.signing_algo,
            signature.signing_address
        ),
    ))
}

fn verify_chat_signature(signature: &ChatSignature) -> Result<(), Error> {
    match signature.signing_algo {
        SigningAlgo::Ecdsa => {
            let message = format!(
                "\x19Ethereum Signed Message:\n{}{}",
                signature.text.len(),
                signature.text
            );
            let message_hash = <sha3::Keccak256 as sha3::Digest>::digest(message.as_bytes());

            let sig_bytes = hex_to_bytes(&signature.signature)?;

            if sig_bytes.len() != 65 {
                return Err(Error::VerificationError(format!(
                    "invalid signature length: expected 65 bytes, got {}",
                    sig_bytes.len()
                )));
            }

            // Ethereum signatures commonly encode recovery `v` as 27/28 (or EIP-155 values 35+).
            // k256 expects recovery id in 0/1 form (y-parity).
            let v_raw = sig_bytes[64];
            let mut v = v_raw;
            if v == 27 || v == 28 {
                v -= 27;
            } else if v >= 35 {
                // EIP-155: v = 35 + 2 * chain_id + parity
                v = (v - 35) % 2;
            }

            let recovery_id = k256::ecdsa::RecoveryId::try_from(v).map_err(|_| {
                Error::VerificationError(format!(
                    "invalid recovery ID: v_raw={}, v_normalized={}",
                    v_raw, v
                ))
            })?;

            let sig =
                k256::ecdsa::Signature::from_bytes((&sig_bytes[..64]).into()).map_err(|_| {
                    Error::VerificationError(
                        "invalid signature format: failed to parse 64-byte r||s".to_owned(),
                    )
                })?;

            let verifying_key =
                k256::ecdsa::VerifyingKey::recover_from_prehash(&message_hash, &sig, recovery_id)
                    .map_err(|_| {
                    Error::VerificationError(format!(
                        "failed to recover public key from signature (v_raw={}, v_normalized={})",
                        v_raw, v
                    ))
                })?;

            // Get address from public key (last 20 bytes of keccak256 hash of public key)
            let public_key_raw = verifying_key.to_sec1_bytes();
            let pubkey_hash = <sha3::Keccak256 as sha3::Digest>::digest(&public_key_raw[1..]); // Skip 0x04 prefix

            let recovered_address: [u8; 20] = pubkey_hash[12..].try_into().map_err(|_| {
                Error::VerificationError(format!(
                    "invalid recovered address length: expected 20 bytes, got {}",
                    pubkey_hash[12..].len()
                ))
            })?;

            let signing_address_raw = hex_to_bytes(&signature.signing_address)?;

            if signing_address_raw.len() != 20 {
                return Err(Error::VerificationError(format!(
                    "invalid signing address length: expected 20 bytes, got {}",
                    signing_address_raw.len()
                )));
            }

            if recovered_address != signing_address_raw.as_slice() {
                let recovered_hex = format!("0x{}", hex::encode(recovered_address));
                let expected_hex = format!("0x{}", hex::encode(&signing_address_raw));
                return Err(Error::VerificationError(
                    format!(
                        "invalid ECDSA chat signature: recovered address mismatch (expected={}, recovered={})",
                        expected_hex, recovered_hex
                    ),
                ));
            }
        }
        SigningAlgo::Ed25519 => {
            let public_key_raw = hex_to_bytes(&signature.signing_address)?;
            let signature_raw = hex_to_bytes(&signature.signature)?;

            if public_key_raw.len() < 32 {
                return Err(Error::VerificationError(format!(
                    "invalid public key length: expected >=32 bytes, got {}",
                    public_key_raw.len()
                )));
            }
            if signature_raw.len() < 64 {
                return Err(Error::VerificationError(format!(
                    "invalid signature length: expected >=64 bytes, got {}",
                    signature_raw.len()
                )));
            }

            let verifying_key =
                ed25519_dalek::VerifyingKey::from_bytes(public_key_raw[..32].try_into().map_err(
                    |_| Error::VerificationError("invalid public key length".to_owned()),
                )?)
                .map_err(|e| Error::VerificationError(format!("invalid public key: {}", e)))?;

            let sig =
                ed25519_dalek::Signature::from_bytes(signature_raw[..64].try_into().map_err(
                    |_| Error::VerificationError("invalid signature length".to_owned()),
                )?);

            ed25519_dalek::Verifier::verify(&verifying_key, signature.text.as_bytes(), &sig)
                .map_err(|_| {
                    Error::VerificationError(
                        "invalid ED25519 chat signature: signature verification failed".to_owned(),
                    )
                })?;
        }
    }

    Ok(())
}

fn verify_chat_hash(text: &str, request_body: &[u8], response_body: &[u8]) -> Result<(), Error> {
    let request_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(request_body));
    let response_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(response_body));
    let expected = format!("{}:{}", request_hash, response_hash);

    if text != expected {
        return Err(Error::VerificationError(format!(
            "chat hash mismatching: expected={}, got={}",
            expected, text
        )));
    }

    Ok(())
}
