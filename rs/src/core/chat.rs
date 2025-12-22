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

    Err(Error::verification(
        "the signature signing algorithm or address does not match any of the model attestations"
            .to_owned(),
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
                return Err(Error::verification("invalid signature length".to_owned()));
            }

            let recovery_id = k256::ecdsa::RecoveryId::try_from(sig_bytes[64])
                .map_err(|_| Error::verification("invalid recovery ID".to_owned()))?;

            let sig = k256::ecdsa::Signature::from_bytes((&sig_bytes[..64]).into())
                .map_err(|_| Error::verification("invalid signature format".to_owned()))?;

            let verifying_key =
                k256::ecdsa::VerifyingKey::recover_from_prehash(&message_hash, &sig, recovery_id)
                    .map_err(|_| Error::verification("failed to recover public key".to_owned()))?;

            // Get address from public key (last 20 bytes of keccak256 hash of public key)
            let public_key_bytes = verifying_key.to_sec1_bytes();
            let pubkey_hash = <sha3::Keccak256 as sha3::Digest>::digest(&public_key_bytes[1..]); // Skip 0x04 prefix
            let recovered_address: [u8; 20] = pubkey_hash[12..]
                .try_into()
                .map_err(|_| Error::verification("invalid recovered address length".to_owned()))?;

            let signing_address_str = signature.signing_address.trim_start_matches("0x");
            let signing_address_bytes = hex::decode(signing_address_str)
                .map_err(|_| Error::verification("invalid signing address format".to_owned()))?;

            if signing_address_bytes.len() != 20 {
                return Err(Error::verification(
                    "invalid signing address length".to_owned(),
                ));
            }
            if recovered_address != signing_address_bytes.as_slice() {
                return Err(Error::verification(
                    "invalid ECDSA chat signature".to_owned(),
                ));
            }
        }
        SigningAlgo::Ed25519 => {
            let public_key_bytes = hex_to_bytes(&signature.signing_address)?;
            let signature_bytes = hex_to_bytes(&signature.signature)?;

            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                public_key_bytes[..32]
                    .try_into()
                    .map_err(|_| Error::verification("invalid public key length".to_owned()))?,
            )
            .map_err(|e| Error::verification(format!("failed to create verifying key: {}", e)))?;

            let sig = ed25519_dalek::Signature::from_bytes(
                signature_bytes[..64]
                    .try_into()
                    .map_err(|_| Error::verification("invalid signature length".to_owned()))?,
            );

            ed25519_dalek::Verifier::verify(&verifying_key, signature.text.as_bytes(), &sig)
                .map_err(|_| Error::verification("invalid ED25519 chat signature".to_owned()))?;
        }
    }

    Ok(())
}

fn verify_chat_hash(text: &str, request_body: &[u8], response_body: &[u8]) -> Result<(), Error> {
    let request_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(request_body));
    let response_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(response_body));
    let expected = format!("{}:{}", request_hash, response_hash);

    if text != expected {
        return Err(Error::verification("chat hash mismatching".to_owned()));
    }

    Ok(())
}
