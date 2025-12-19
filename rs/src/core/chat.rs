use crate::types::attestation_model::ModelAttestation;
use crate::types::chat::{Chat, ChatSignature};
use crate::types::attestation_common::SigningAlgo;
use crate::utils::common::hex_to_bytes;
use crate::utils::errors::VerificationError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn verify_chat(message: &Chat, signature: &ChatSignature) -> Result<(), VerificationError> {
    verify_chat_hash(&signature.text, &message.request_body, &message.response_body)?;
    verify_chat_signature(signature)?;
    Ok(())
}

pub fn verify_signing_address(
    signature: &ChatSignature,
    attestations: &[ModelAttestation],
) -> Result<(), VerificationError> {
    for attestation in attestations {
        if signature.signing_algo == attestation.signing_algo {
            let sig_addr_bytes = hex_to_bytes(&signature.signing_address)?;
            let att_addr_bytes = hex_to_bytes(&attestation.signing_address)?;

            if sig_addr_bytes == att_addr_bytes {
                return Ok(());
            }
        }
    }

    Err(VerificationError::new(
        "The signature signing algorithm or address does not match any of the model attestations".to_string(),
    ))
}

fn verify_chat_signature(signature: &ChatSignature) -> Result<(), VerificationError> {
    match signature.signing_algo {
        SigningAlgo::Ecdsa => {
            use alloy_primitives::Address;
            use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey};
            use sha3::{Keccak256, Digest};

            // Create Ethereum message hash
            let message = format!("\x19Ethereum Signed Message:\n{}{}", signature.text.len(), signature.text);
            let message_hash = Keccak256::digest(message.as_bytes());

            let sig_bytes = hex_to_bytes(&signature.signature)?;
            
            if sig_bytes.len() != 65 {
                return Err(VerificationError::new("Invalid signature length".to_string()));
            }

            let recovery_id = RecoveryId::try_from(sig_bytes[64])
                .map_err(|_| VerificationError::new("Invalid recovery ID".to_string()))?;

            let sig = EcdsaSignature::from_bytes((&sig_bytes[..64]).into())
                .map_err(|_| VerificationError::new("Invalid signature format".to_string()))?;

            let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &sig, recovery_id)
                .map_err(|_| VerificationError::new("Failed to recover public key".to_string()))?;

            // Get address from public key (last 20 bytes of keccak256 hash of public key)
            let public_key_bytes = verifying_key.to_sec1_bytes();
            let pubkey_hash = Keccak256::digest(&public_key_bytes[1..]); // Skip 0x04 prefix
            let recovered_address = Address::from_slice(&pubkey_hash[12..]);

            let signing_address_str = signature.signing_address.trim_start_matches("0x");
            let signing_address_bytes = hex::decode(signing_address_str)
                .map_err(|_| VerificationError::new("Invalid signing address format".to_string()))?;
            
            if signing_address_bytes.len() != 20 {
                return Err(VerificationError::new("Invalid signing address length".to_string()));
            }

            let signing_address = Address::from_slice(&signing_address_bytes);

            if recovered_address != signing_address {
                return Err(VerificationError::new("Invalid ECDSA chat signature".to_string()));
            }
        }
        SigningAlgo::Ed25519 => {
            let public_key_bytes = hex_to_bytes(&signature.signing_address)?;
            let signature_bytes = hex_to_bytes(&signature.signature)?;

            let verifying_key = VerifyingKey::from_bytes(
                public_key_bytes[..32]
                    .try_into()
                    .map_err(|_| VerificationError::new("Invalid public key length".to_string()))?,
            )
            .map_err(|e| VerificationError::new(format!("Failed to create verifying key: {}", e)))?;

            let sig = Signature::from_bytes(
                signature_bytes[..64]
                    .try_into()
                    .map_err(|_| VerificationError::new("Invalid signature length".to_string()))?,
            )
            .map_err(|e| VerificationError::new(format!("Failed to create signature: {}", e)))?;

            verifying_key
                .verify(signature.text.as_bytes(), &sig)
                .map_err(|_| VerificationError::new("Invalid ED25519 chat signature".to_string()))?;
        }
    }

    Ok(())
}

fn verify_chat_hash(text: &str, request_body: &[u8], response_body: &[u8]) -> Result<(), VerificationError> {
    let request_hash = hex::encode(Sha256::digest(request_body));
    let response_hash = hex::encode(Sha256::digest(response_body));
    let expected = format!("{}:{}", request_hash, response_hash);

    if text != expected {
        return Err(VerificationError::new("Chat hash mismatching".to_string()));
    }

    Ok(())
}

