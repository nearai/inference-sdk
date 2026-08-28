use crate::errors::VerificationError;
use crate::types::{GatewayTlsBinding, ModelTlsBinding, SigningAlgo, SigningIdentity};
use crate::util::{require_hex_length, sha256};

pub fn verify_reported_nonce(
    reported_nonce: &str,
    nonce: &str,
    source: &'static str,
) -> Result<(), VerificationError> {
    let expected = require_hex_length(nonce, 32).map_err(|_| VerificationError::InvalidInput {
        field: "nonce".to_owned(),
        reason: "expected a 32-byte hexadecimal nonce".to_owned(),
    })?;
    let reported =
        require_hex_length(reported_nonce, 32).map_err(|_| VerificationError::InvalidInput {
            field: match source {
                "nvidia_payload" => "nvidia_payload.nonce".to_owned(),
                _ => "attestation.nonce".to_owned(),
            },
            reason: "expected a 32-byte hexadecimal nonce".to_owned(),
        })?;
    if expected != reported {
        return Err(VerificationError::NonceMismatch { binding: source });
    }
    Ok(())
}

pub fn validate_signing_identity(
    signer: &SigningIdentity,
) -> Result<SigningIdentity, VerificationError> {
    let expected_length = match signer.signing_algo {
        SigningAlgo::Ecdsa => 20,
        SigningAlgo::Ed25519 => 32,
    };
    require_hex_length(&signer.signing_address, expected_length).map_err(|_| {
        VerificationError::InvalidInput {
            field: "attestation.signer.signing_address".to_owned(),
            reason: format!("expected a {expected_length}-byte hexadecimal signing address"),
        }
    })?;
    Ok(signer.clone())
}

pub fn verify_advertised_report_data(
    advertised_report_data: Option<&str>,
    quote_report_data: &[u8],
) -> Result<(), VerificationError> {
    let Some(advertised_report_data) = advertised_report_data else {
        return Ok(());
    };
    let advertised = require_hex_length(advertised_report_data, 64).map_err(|_| {
        VerificationError::ReportDataInvalid {
            reason: "reported_quote_data",
        }
    })?;
    if advertised != quote_report_data {
        return Err(VerificationError::ReportDataMismatch {
            binding: "reported_quote_data",
        });
    }
    Ok(())
}

pub fn verify_gateway_report_data_binding(
    report_data: &[u8],
    nonce: &str,
    signing_address: &str,
    reported_spki_fingerprint: &str,
    peer_spki_fingerprint: Option<&str>,
) -> Result<GatewayTlsBinding, VerificationError> {
    verify_quote_report_data_nonce(report_data, nonce)?;
    let reported = require_hex_length(reported_spki_fingerprint, 32).map_err(|_| {
        VerificationError::InvalidInput {
            field: "attestation.declared_spki_fingerprint".to_owned(),
            reason: "expected a 32-byte hexadecimal SPKI fingerprint".to_owned(),
        }
    })?;
    let signing_address = decode_signing_address(signing_address)?;
    let mut binding_data = signing_address;
    binding_data.extend_from_slice(&reported);
    if report_data[..32] != sha256(binding_data) {
        return Err(VerificationError::ReportDataMismatch {
            binding: "signer_tls_binding",
        });
    }
    let Some(peer_spki_fingerprint) = peer_spki_fingerprint else {
        return Ok(GatewayTlsBinding::Attested {
            spki_fingerprint: hex::encode(reported),
        });
    };
    let peer = require_hex_length(peer_spki_fingerprint, 32).map_err(|_| {
        VerificationError::InvalidInput {
            field: "client_binding.peer_spki_fingerprint".to_owned(),
            reason: "expected a 32-byte hexadecimal SPKI fingerprint".to_owned(),
        }
    })?;
    if reported != peer {
        return Err(VerificationError::SpkiFingerprintMismatch);
    }
    Ok(GatewayTlsBinding::Peer {
        spki_fingerprint: hex::encode(reported),
    })
}

pub fn verify_cloud_model_report_data_binding(
    report_data: &[u8],
    nonce: &str,
    signing_address: &str,
    reported_spki_fingerprint: Option<&str>,
) -> Result<ModelTlsBinding, VerificationError> {
    verify_quote_report_data_nonce(report_data, nonce)?;

    let signing_address = decode_signing_address(signing_address)?;
    if let Some(fingerprint) = reported_spki_fingerprint {
        let fingerprint =
            require_hex_length(fingerprint, 32).map_err(|_| VerificationError::InvalidInput {
                field: "attestation.declared_spki_fingerprint".to_owned(),
                reason: "expected a 32-byte hexadecimal SPKI fingerprint".to_owned(),
            })?;
        let mut binding_data = signing_address;
        binding_data.extend_from_slice(&fingerprint);
        if report_data[..32] != sha256(binding_data) {
            return Err(VerificationError::ReportDataMismatch {
                binding: "signer_tls_binding",
            });
        }
        return Ok(ModelTlsBinding::Declared {
            spki_fingerprint: hex::encode(fingerprint),
        });
    }

    let mut expected = vec![0u8; 32];
    expected[..signing_address.len()].copy_from_slice(&signing_address);
    if report_data[..32] != expected {
        return Err(VerificationError::ReportDataMismatch {
            binding: "signer_binding",
        });
    }
    Ok(ModelTlsBinding::None)
}

pub fn verify_app_compose_mrconfigid_binding(
    app_compose: &str,
    mr_config_id: &[u8],
) -> Result<(), VerificationError> {
    if mr_config_id.len() < 33 {
        return Err(VerificationError::MrConfigIdInvalid {
            reason: "wrong_length",
        });
    }
    if mr_config_id[0] != 0x01 {
        return Err(VerificationError::MrConfigIdInvalid {
            reason: "unsupported_version",
        });
    }
    let expected = sha256(app_compose.as_bytes());
    if mr_config_id[1..33] != expected {
        return Err(VerificationError::AppComposeMrConfigIdMismatch);
    }
    Ok(())
}

fn verify_quote_report_data_nonce(
    report_data: &[u8],
    nonce: &str,
) -> Result<(), VerificationError> {
    if report_data.len() != 64 {
        return Err(VerificationError::ReportDataInvalid {
            reason: "quote_report_data",
        });
    }
    let expected_nonce =
        require_hex_length(nonce, 32).map_err(|_| VerificationError::InvalidInput {
            field: "nonce".to_owned(),
            reason: "expected a 32-byte hexadecimal nonce".to_owned(),
        })?;
    if report_data[32..64] != expected_nonce {
        return Err(VerificationError::NonceMismatch {
            binding: "quote_report_data",
        });
    }
    Ok(())
}

fn decode_signing_address(value: &str) -> Result<Vec<u8>, VerificationError> {
    crate::util::decode_hex(value).map_err(|_| VerificationError::InvalidInput {
        field: "attestation.signer.signing_address".to_owned(),
        reason: "expected hexadecimal signing address".to_owned(),
    })
}
