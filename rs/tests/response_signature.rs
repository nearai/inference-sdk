mod support;

use nearai_inference_sdk::{
    verify_gateway_response, verify_model_response, CompletionSignature, CompletionSignatureKind,
    SigningAlgo, SigningIdentity, VerificationError,
};
use sha3::Digest as _;
use support::{
    sha256_hex, signed_signature, verified_gateway_attestation, verified_model_attestation,
};

fn sign(algo: SigningAlgo, kind: CompletionSignatureKind, text: String) -> CompletionSignature {
    match algo {
        SigningAlgo::Ed25519 => {
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let signer = SigningIdentity {
                signing_algo: algo,
                signing_address: hex::encode(key.verifying_key().to_bytes()),
            };
            signed_signature(&key, kind, text, signer)
        }
        SigningAlgo::Ecdsa => {
            let key = k256::ecdsa::SigningKey::from_bytes((&[1; 32]).into()).unwrap();
            let mut personal_message =
                format!("\x19Ethereum Signed Message:\n{}", text.len()).into_bytes();
            personal_message.extend_from_slice(text.as_bytes());
            let digest = sha3::Keccak256::digest(personal_message);
            let (signature, recovery_id) = key.sign_prehash_recoverable(&digest);
            let mut signature_bytes = signature.to_bytes().to_vec();
            signature_bytes.push(u8::from(recovery_id) + 27);
            let public_key = key.verifying_key().to_sec1_point(false);
            let hash = sha3::Keccak256::digest(&public_key.as_bytes()[1..]);
            CompletionSignature {
                kind,
                signed_text: text,
                signature: hex::encode(signature_bytes),
                signer: SigningIdentity {
                    signing_algo: algo,
                    signing_address: hex::encode(&hash[12..]),
                },
            }
        }
    }
}

#[test]
fn binds_both_signature_kinds_to_exact_bytes_and_the_attested_signer() {
    let request = br#"{"model":"glm-5.3-flash","messages":[]}"#;
    let response = br#"{"id":"response"}"#;
    for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
        for kind in [
            CompletionSignatureKind::ProviderTee,
            CompletionSignatureKind::Gateway,
        ] {
            let hashes = format!("{}:{}", sha256_hex(request), sha256_hex(response));
            let text = match kind {
                CompletionSignatureKind::ProviderTee => format!("glm-5.3-flash:{hashes}"),
                CompletionSignatureKind::Gateway => hashes,
            };
            let signature = sign(algo, kind, text);
            let signer = signature.signer.clone();
            let verify = |request: &[u8],
                          response: &[u8],
                          signature: &CompletionSignature,
                          signer: &SigningIdentity| {
                match kind {
                    CompletionSignatureKind::ProviderTee => verify_model_response(
                        request,
                        response,
                        signature,
                        &verified_model_attestation(signer.clone()),
                    ),
                    CompletionSignatureKind::Gateway => verify_gateway_response(
                        request,
                        response,
                        signature,
                        &verified_gateway_attestation(signer.clone()),
                    ),
                }
            };
            verify(request, response, &signature, &signer).unwrap();

            let mut normalized = signature.clone();
            normalized.signer.signing_address =
                format!("0X{}", signer.signing_address.to_uppercase());
            normalized.signature = format!("0X{}", signature.signature.to_uppercase());
            verify(request, response, &normalized, &signer).unwrap();

            for (changed_request, changed_response) in [
                (
                    &br#"{"model":"glm-5.3-flash","messages":[{}]}"#[..],
                    &response[..],
                ),
                (&request[..], &br#"{"id":"changed"}"#[..]),
            ] {
                assert!(matches!(
                    verify(changed_request, changed_response, &signature, &signer),
                    Err(VerificationError::SignaturePayloadMismatch {
                        reason: "text_mismatch"
                    })
                ));
            }

            let mut changed_signature = signature.clone();
            let mut bytes = hex::decode(&signature.signature).unwrap();
            bytes[0] ^= 1;
            changed_signature.signature = hex::encode(bytes);
            assert!(matches!(
                verify(request, response, &changed_signature, &signer),
                Err(VerificationError::SignatureInvalid { signing_algo }) if signing_algo == algo
            ));
            for malformed in ["gg".to_owned(), "00".to_owned()] {
                changed_signature.signature = malformed;
                assert!(matches!(
                    verify(request, response, &changed_signature, &signer),
                    Err(VerificationError::SignatureFormatInvalid {
                        field: "signature",
                        ..
                    })
                ));
            }

            let mut different_signer = signer.clone();
            different_signer.signing_address = "11".repeat(signer.signing_address.len() / 2);
            assert!(matches!(
                verify(request, response, &signature, &different_signer),
                Err(VerificationError::SignatureSignerMismatch)
            ));
            different_signer = signer.clone();
            different_signer.signing_algo = match algo {
                SigningAlgo::Ed25519 => SigningAlgo::Ecdsa,
                SigningAlgo::Ecdsa => SigningAlgo::Ed25519,
            };
            assert!(matches!(
                verify(request, response, &signature, &different_signer),
                Err(VerificationError::SignatureSignerMismatch)
            ));

            let mut wrong_kind = signature.clone();
            wrong_kind.kind = match kind {
                CompletionSignatureKind::ProviderTee => CompletionSignatureKind::Gateway,
                CompletionSignatureKind::Gateway => CompletionSignatureKind::ProviderTee,
            };
            assert!(matches!(
                verify(request, response, &wrong_kind, &signer),
                Err(VerificationError::SignatureKindMismatch { expected, actual })
                    if expected == kind && actual == wrong_kind.kind
            ));

            if kind == CompletionSignatureKind::ProviderTee {
                for (request, reason) in [
                    (&b"invalid"[..], "invalid_json"),
                    (&b"{}"[..], "missing_model"),
                    (&br#"{"model":""}"#[..], "missing_model"),
                ] {
                    assert!(matches!(
                        verify(request, response, &signature, &signer),
                        Err(VerificationError::SignaturePayloadMismatch { reason: actual }) if actual == reason
                    ));
                }
            }
        }
    }
}
