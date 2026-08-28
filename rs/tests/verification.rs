use async_trait::async_trait;
use ed25519_dalek::Signer;
use sha2::Digest;
use verification_sdk::{
    verify_gateway_attestation, verify_gateway_response, verify_model_attestation,
    verify_model_response, AttestationEventLog, AttestationEvidence, AttestationPolicy,
    AttestationVerifiers, CompletionSignature, CompletionSignatureKind, DeploymentProvenanceStatus,
    GatewayAttestation, GpuEvidenceRequirement, GpuEvidenceStatus, ModelAttestation,
    ModelAttestationPolicy, ModelAttestationVerifiers, ModelTlsBinding, NvidiaEvidenceVerifier,
    QuoteVerificationResult, QuoteVerifier, SigningAlgo, SigningIdentity, TcbStatus,
    VerificationError, VerifiedAttestationEvidence, VerifiedGatewayAttestation,
    VerifiedModelAttestation, VerifyGatewayAttestationInput, VerifyGatewayResponseInput,
    VerifyModelAttestationInput, VerifyModelResponseInput,
};

const NONCE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ECDSA_ADDRESS: &str = "2222222222222222222222222222222222222222";
const TLS_FINGERPRINT: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const APP_COMPOSE: &str = "{\"services\":{\"model\":\"example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}";

#[derive(Clone)]
struct FixtureQuoteVerifier(QuoteVerificationResult);

#[async_trait]
impl QuoteVerifier for FixtureQuoteVerifier {
    async fn verify(
        &self,
        _intel_quote: &str,
    ) -> Result<QuoteVerificationResult, VerificationError> {
        Ok(self.0.clone())
    }
}

struct FixtureNvidiaVerifier;

#[async_trait]
impl NvidiaEvidenceVerifier for FixtureNvidiaVerifier {
    async fn verify(&self, _nvidia_payload: &str) -> Result<(), VerificationError> {
        Ok(())
    }
}

#[tokio::test]
async fn model_attestation_accepts_missing_gpu_evidence() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::OutOfDate));
    let attestation = model_attestation(None, false);

    let verified = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap();

    assert_eq!(verified.evidence.tcb_status, TcbStatus::OutOfDate);
    assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::NotProvided);
    assert_eq!(verified.tls_binding, ModelTlsBinding::None);
    assert_eq!(
        verified.evidence.deployment_provenance,
        DeploymentProvenanceStatus::NotChecked
    );
}

#[tokio::test]
async fn model_attestation_accepts_tls_bound_report_data() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = model_attestation(None, true);

    let verified = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap();

    assert_eq!(
        verified.tls_binding,
        ModelTlsBinding::Declared {
            spki_fingerprint: TLS_FINGERPRINT.to_owned(),
        }
    );
}

#[tokio::test]
async fn model_attestation_does_not_downgrade_declared_tls_to_legacy_binding() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let mut attestation = model_attestation(None, true);
    attestation.evidence.reported_quote_data = None;

    let error = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ReportDataMismatch {
            binding: "signer_tls_binding"
        }
    ));
}

#[tokio::test]
async fn model_attestation_rejects_empty_gpu_payload_before_calling_a_verifier() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let attestation = model_attestation(Some(""), false);

    let error = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::GpuPayloadInvalid {
            reason: "invalid_json"
        }
    ));
}

#[tokio::test]
async fn model_attestation_enforces_required_gpu_policy() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let attestation = model_attestation(None, false);
    let policy = ModelAttestationPolicy {
        accepted_tcb_statuses: None,
        gpu_evidence: GpuEvidenceRequirement::Required,
    };

    let error = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: Some(&policy),
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::GpuEvidenceRequired));
}

#[tokio::test]
async fn model_attestation_verifies_supplied_gpu_evidence_with_a_custom_verifier() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let nvidia = FixtureNvidiaVerifier;
    let payload = format!(r#"{{"nonce":"{NONCE}"}}"#);
    let attestation = model_attestation(Some(&payload), false);

    let verified = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            nvidia: Some(&nvidia),
            ..Default::default()
        },
    })
    .await
    .unwrap();

    assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::Verified);
}

#[tokio::test]
async fn model_attestation_rejects_incoherent_advertised_report_data() {
    let quote = FixtureQuoteVerifier(model_quote(false, TcbStatus::UpToDate));
    let mut incoherent = model_attestation(None, false);
    incoherent.evidence.reported_quote_data = Some("00".repeat(64));

    let error = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &incoherent,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::ReportDataMismatch {
            binding: "reported_quote_data"
        }
    ));
}

#[tokio::test]
async fn model_attestation_replays_rtmr3_measurements() {
    let mut quote = model_quote(false, TcbStatus::UpToDate);
    quote.rt_mr3[0] ^= 1;
    let quote = FixtureQuoteVerifier(quote);
    let attestation = model_attestation(None, false);
    let error = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::Rtmr3Mismatch {
            reason: "replay_mismatch"
        }
    ));
}

#[tokio::test]
async fn model_attestation_rejects_an_app_compose_not_bound_by_mrconfigid() {
    let mut quote = model_quote(false, TcbStatus::UpToDate);
    quote.mr_config_id[1] ^= 1;
    let quote = FixtureQuoteVerifier(quote);
    let attestation = model_attestation(None, false);

    let error = verify_model_attestation(VerifyModelAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        policy: None,
        verifiers: ModelAttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::AppComposeMrConfigIdMismatch
    ));
}

#[tokio::test]
async fn gateway_attestation_binds_the_observed_tls_peer() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let verified = verify_gateway_attestation(VerifyGatewayAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        peer_spki_fingerprint: TLS_FINGERPRINT,
        policy: Some(&AttestationPolicy::default()),
        verifiers: AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap();

    assert_eq!(verified.tls_binding.spki_fingerprint, TLS_FINGERPRINT);
}

#[tokio::test]
async fn gateway_attestation_rejects_another_tls_peer() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let attestation = gateway_attestation();

    let error = verify_gateway_attestation(VerifyGatewayAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        peer_spki_fingerprint: "44".repeat(32).as_str(),
        policy: None,
        verifiers: AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::SpkiFingerprintMismatch));
}

#[tokio::test]
async fn gateway_attestation_rejects_an_empty_declared_tls_fingerprint() {
    let quote = FixtureQuoteVerifier(model_quote(true, TcbStatus::UpToDate));
    let mut attestation = gateway_attestation();
    attestation.evidence.declared_spki_fingerprint = Some(String::new());

    let error = verify_gateway_attestation(VerifyGatewayAttestationInput {
        attestation: &attestation,
        nonce: NONCE,
        peer_spki_fingerprint: TLS_FINGERPRINT,
        policy: None,
        verifiers: AttestationVerifiers {
            quote: Some(&quote),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::SpkiFingerprintMissing));
}

#[test]
fn response_signatures_use_distinct_model_and_gateway_payloads() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let signing_address = hex::encode(signing_key.verifying_key().to_bytes());
    let request_body = br#"{"model":"glm-5.2","messages":[]}"#;
    let response_body = br#"{"id":"response"}"#;
    let signer = SigningIdentity {
        signing_algo: SigningAlgo::Ed25519,
        signing_address,
    };
    let model_signature = signed_signature(
        &signing_key,
        CompletionSignatureKind::ProviderTee,
        format!(
            "glm-5.2:{}:{}",
            sha256_hex(request_body),
            sha256_hex(response_body)
        ),
        signer.clone(),
    );
    let gateway_signature = signed_signature(
        &signing_key,
        CompletionSignatureKind::Gateway,
        format!("{}:{}", sha256_hex(request_body), sha256_hex(response_body)),
        signer.clone(),
    );
    let model_attestation = verified_model_attestation(signer.clone());
    let gateway_attestation = verified_gateway_attestation(signer);

    verify_model_response(VerifyModelResponseInput {
        request_body,
        response_body,
        signature: &model_signature,
        attestation: &model_attestation,
    })
    .unwrap();
    verify_gateway_response(VerifyGatewayResponseInput {
        request_body,
        response_body,
        signature: &gateway_signature,
        attestation: &gateway_attestation,
    })
    .unwrap();

    let error = verify_model_response(VerifyModelResponseInput {
        request_body,
        response_body,
        signature: &gateway_signature,
        attestation: &model_attestation,
    })
    .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::SignatureKindMismatch {
            expected: CompletionSignatureKind::ProviderTee,
            actual: CompletionSignatureKind::Gateway,
        }
    ));
}

#[test]
fn model_response_accepts_an_ethereum_personal_signature() {
    let signing_key = k256::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let request_body = br#"{"model":"glm-5.2","messages":[]}"#;
    let response_body = br#"{"id":"response"}"#;
    let signed_text = format!(
        "glm-5.2:{}:{}",
        sha256_hex(request_body),
        sha256_hex(response_body)
    );
    let mut personal_message =
        format!("\x19Ethereum Signed Message:\n{}", signed_text.len()).into_bytes();
    personal_message.extend_from_slice(signed_text.as_bytes());
    let digest = sha3::Keccak256::digest(personal_message);
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
    let mut signature_bytes = signature.to_bytes().to_vec();
    signature_bytes.push(u8::from(recovery_id) + 27);

    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key_hash = sha3::Keccak256::digest(&public_key.as_bytes()[1..]);
    let signer = SigningIdentity {
        signing_algo: SigningAlgo::Ecdsa,
        signing_address: hex::encode(&public_key_hash[12..]),
    };
    let completion_signature = CompletionSignature {
        kind: CompletionSignatureKind::ProviderTee,
        signed_text,
        signature: hex::encode(signature_bytes),
        signer: signer.clone(),
    };
    let attestation = verified_model_attestation(signer);

    verify_model_response(VerifyModelResponseInput {
        request_body,
        response_body,
        signature: &completion_signature,
        attestation: &attestation,
    })
    .unwrap();
}

fn model_attestation(nvidia_payload: Option<&str>, with_tls_fingerprint: bool) -> ModelAttestation {
    let report_data =
        hex::encode(model_quote(with_tls_fingerprint, TcbStatus::UpToDate).report_data);
    ModelAttestation {
        evidence: AttestationEvidence {
            nonce: NONCE.to_owned(),
            signer: SigningIdentity {
                signing_algo: SigningAlgo::Ecdsa,
                signing_address: ECDSA_ADDRESS.to_owned(),
            },
            intel_quote: "fixture".to_owned(),
            event_log: AttestationEventLog::Entries(vec![serde_json::json!({
                "digest": "00".repeat(48),
                "imr": 3,
            })]),
            app_compose: APP_COMPOSE.to_owned(),
            declared_spki_fingerprint: with_tls_fingerprint.then(|| TLS_FINGERPRINT.to_owned()),
            reported_quote_data: Some(report_data),
        },
        nvidia_payload: nvidia_payload.map(ToOwned::to_owned),
    }
}

fn gateway_attestation() -> GatewayAttestation {
    let quote = model_quote(true, TcbStatus::UpToDate);
    let reported_quote_data = hex::encode(&quote.report_data);
    GatewayAttestation {
        evidence: AttestationEvidence {
            nonce: NONCE.to_owned(),
            signer: SigningIdentity {
                signing_algo: SigningAlgo::Ecdsa,
                signing_address: ECDSA_ADDRESS.to_owned(),
            },
            intel_quote: "fixture".to_owned(),
            event_log: AttestationEventLog::Entries(vec![serde_json::json!({
                "digest": "00".repeat(48),
                "imr": 3,
            })]),
            app_compose: APP_COMPOSE.to_owned(),
            declared_spki_fingerprint: Some(TLS_FINGERPRINT.to_owned()),
            reported_quote_data: Some(reported_quote_data.clone()),
        },
        reported_quote_data,
    }
}

fn model_quote(with_tls_fingerprint: bool, tcb_status: TcbStatus) -> QuoteVerificationResult {
    let mut report_data = Vec::new();
    if with_tls_fingerprint {
        let mut input = hex::decode(ECDSA_ADDRESS).unwrap();
        input.extend(hex::decode(TLS_FINGERPRINT).unwrap());
        report_data.extend(sha256_bytes(&input));
    } else {
        report_data.extend(hex::decode(ECDSA_ADDRESS).unwrap());
        report_data.extend([0u8; 12]);
    }
    report_data.extend(hex::decode(NONCE).unwrap());

    let event_digest = vec![0u8; 48];
    let mut rtmr_input = vec![0u8; 48];
    rtmr_input.extend(event_digest);
    let mut mr_config_id = vec![0x01];
    mr_config_id.extend(sha256_bytes(APP_COMPOSE.as_bytes()));
    mr_config_id.extend([0u8; 15]);

    QuoteVerificationResult {
        tcb_status,
        advisory_ids: vec![],
        debug_enabled: false,
        report_data,
        mr_config_id,
        rt_mr3: sha384_bytes(&rtmr_input),
    }
}

fn signed_signature(
    signing_key: &ed25519_dalek::SigningKey,
    kind: CompletionSignatureKind,
    signed_text: String,
    signer: SigningIdentity,
) -> CompletionSignature {
    CompletionSignature {
        kind,
        signature: hex::encode(signing_key.sign(signed_text.as_bytes()).to_bytes()),
        signed_text,
        signer,
    }
}

fn verified_model_attestation(signer: SigningIdentity) -> VerifiedModelAttestation {
    VerifiedModelAttestation {
        evidence: verified_evidence(signer),
        tls_binding: ModelTlsBinding::None,
        gpu_evidence: GpuEvidenceStatus::NotProvided,
    }
}

fn verified_gateway_attestation(signer: SigningIdentity) -> VerifiedGatewayAttestation {
    VerifiedGatewayAttestation {
        evidence: verified_evidence(signer),
        tls_binding: verification_sdk::GatewayTlsBinding {
            spki_fingerprint: TLS_FINGERPRINT.to_owned(),
        },
    }
}

fn verified_evidence(signer: SigningIdentity) -> VerifiedAttestationEvidence {
    VerifiedAttestationEvidence {
        signer,
        tcb_status: TcbStatus::UpToDate,
        advisory_ids: vec![],
        deployment: verification_sdk::MeasuredDeployment {
            app_compose: APP_COMPOSE.to_owned(),
            runtime_measurements: Default::default(),
        },
        deployment_provenance: DeploymentProvenanceStatus::NotChecked,
    }
}

fn sha256_bytes(value: impl AsRef<[u8]>) -> Vec<u8> {
    sha2::Sha256::digest(value.as_ref()).to_vec()
}

fn sha384_bytes(value: impl AsRef<[u8]>) -> Vec<u8> {
    sha2::Sha384::digest(value.as_ref()).to_vec()
}

fn sha256_hex(value: impl AsRef<[u8]>) -> String {
    hex::encode(sha256_bytes(value))
}
