mod support;

use async_trait::async_trait;
use nearai_inference_sdk::{
    verify_model_attestation, AttestationEventLog, DeploymentProvenanceStatus, DeploymentVerifier,
    GpuEvidenceRequirement, GpuEvidenceStatus, GpuEvidenceVerifier, MeasuredDeployment,
    ModelAttestationPolicy, ModelAttestationVerifiers, ModelClientBinding, SigningAlgo, TcbStatus,
    VerificationError,
};
use sha2::Digest as _;
use support::{
    gateway_tls_quote, model_attestation, model_quote, FixtureGpuVerifier, FixtureTdxQuoteVerifier,
    APP_COMPOSE, NONCE,
};

fn client_binding() -> ModelClientBinding {
    ModelClientBinding {
        nonce: NONCE.to_owned(),
    }
}

struct ExpectedDeploymentVerifier;

#[async_trait]
impl DeploymentVerifier for ExpectedDeploymentVerifier {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        if deployment.app_compose == APP_COMPOSE {
            Ok(())
        } else {
            Err(VerificationError::DeploymentProvenanceRejected)
        }
    }
}

#[tokio::test]
async fn accepts_missing_gpu_evidence() {
    let tdx_quote = FixtureTdxQuoteVerifier(model_quote(TcbStatus::OutOfDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();

    let verified = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(*verified.report, attestation);
    assert_eq!(verified.evidence.tcb_status, TcbStatus::OutOfDate);
    assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::NotProvided);
    assert_eq!(
        verified.evidence.deployment_provenance,
        DeploymentProvenanceStatus::NotChecked
    );
}

#[tokio::test]
async fn runs_a_model_deployment_verifier() {
    let tdx_quote = FixtureTdxQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    let deployment = ExpectedDeploymentVerifier;

    let verified = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            deployment: Some(&deployment),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        verified.evidence.deployment_provenance,
        DeploymentProvenanceStatus::Verified
    );
}

#[tokio::test]
async fn enforces_the_model_tcb_policy() {
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    for (status, accepted_by_default) in [
        (TcbStatus::OutOfDate, true),
        (TcbStatus::TdRelaunchAdvised, true),
        (TcbStatus::TdRelaunchAdvisedConfigurationNeeded, false),
        (TcbStatus::Unknown, false),
    ] {
        let tdx_quote = FixtureTdxQuoteVerifier(model_quote(status));
        for (accepted, should_accept) in [
            (None, accepted_by_default),
            (Some(vec![status]), true),
            (Some(vec![TcbStatus::UpToDate]), false),
        ] {
            let policy = ModelAttestationPolicy {
                accepted_tcb_statuses: accepted,
                ..Default::default()
            };
            let result = verify_model_attestation(
                &attestation,
                &client_binding,
                Some(&policy),
                ModelAttestationVerifiers {
                    tdx_quote: Some(&tdx_quote),
                    ..Default::default()
                },
            )
            .await;
            if should_accept {
                assert_eq!(result.unwrap().evidence.tcb_status, status);
            } else {
                assert!(matches!(
                    result,
                    Err(VerificationError::TcbStatusNotAllowed { actual, .. })
                        if actual == status
                ));
            }
        }
    }
}

#[tokio::test]
async fn rejects_tls_bound_report_data_for_cloud_model_evidence() {
    let tdx_quote = FixtureTdxQuoteVerifier(gateway_tls_quote(TcbStatus::UpToDate));
    let mut attestation = model_attestation(None);
    let client_binding = client_binding();
    attestation.reported_quote_data = None;

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        VerificationError::ReportDataMismatch {
            binding: "signer_binding"
        }
    ));
}

#[tokio::test]
async fn rejects_an_empty_gpu_payload() {
    let tdx_quote = FixtureTdxQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let attestation = model_attestation(Some(""));
    let client_binding = client_binding();

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            ..Default::default()
        },
    )
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
async fn enforces_required_gpu_policy() {
    let tdx_quote = FixtureTdxQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let attestation = model_attestation(None);
    let client_binding = client_binding();
    let policy = ModelAttestationPolicy {
        accepted_tcb_statuses: None,
        gpu_evidence: GpuEvidenceRequirement::Required,
    };

    let error = verify_model_attestation(
        &attestation,
        &client_binding,
        Some(&policy),
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(error, VerificationError::GpuEvidenceRequired));
}

#[tokio::test]
async fn verifies_supplied_gpu_evidence_with_a_custom_verifier() {
    let tdx_quote = FixtureTdxQuoteVerifier(model_quote(TcbStatus::UpToDate));
    let gpu_evidence = FixtureGpuVerifier;
    let payload = format!(r#"{{"nonce":"{NONCE}"}}"#);
    let attestation = model_attestation(Some(&payload));
    let client_binding = client_binding();

    let verified = verify_model_attestation(
        &attestation,
        &client_binding,
        None,
        ModelAttestationVerifiers {
            tdx_quote: Some(&tdx_quote),
            gpu_evidence: Some(&gpu_evidence),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(verified.gpu_evidence, GpuEvidenceStatus::Verified);
}

#[tokio::test]
async fn checks_the_client_nonce_before_calling_a_custom_gpu_verifier() {
    struct UnreachableGpuVerifier;

    #[async_trait]
    impl GpuEvidenceVerifier for UnreachableGpuVerifier {
        async fn verify(&self, _payload: &str) -> Result<(), VerificationError> {
            panic!("invalid payload nonces must be rejected before the override runs");
        }
    }

    let tdx_quote = FixtureTdxQuoteVerifier(model_quote(TcbStatus::UpToDate));
    for nonce in ["22".repeat(32), "11".repeat(31), "gg".repeat(32)] {
        let payload = serde_json::json!({"nonce": nonce}).to_string();
        let error = verify_model_attestation(
            &model_attestation(Some(&payload)),
            &client_binding(),
            None,
            ModelAttestationVerifiers {
                tdx_quote: Some(&tdx_quote),
                gpu_evidence: Some(&UnreachableGpuVerifier),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        match error {
            VerificationError::NonceMismatch {
                binding: "nvidia_payload",
            } => {}
            VerificationError::InvalidInput { field, .. } if field == "nvidia_payload.nonce" => {}
            error => panic!("unexpected error: {error}"),
        }
    }
}

#[tokio::test]
async fn rejects_unbound_evidence_before_running_deployment_policy() {
    struct UnreachableDeploymentVerifier;
    #[async_trait]
    impl DeploymentVerifier for UnreachableDeploymentVerifier {
        async fn verify(&self, _: &MeasuredDeployment) -> Result<(), VerificationError> {
            panic!("invalid base evidence must not reach deployment policy");
        }
    }
    for (case, expected_code, expected_detail) in [
        (
            "echoed nonce",
            "binding.nonce_mismatch",
            "attestation_nonce",
        ),
        ("debug quote", "policy.debug_enabled", ""),
        (
            "advertised report",
            "binding.report_data_mismatch",
            "reported_quote_data",
        ),
        (
            "short advertised report",
            "binding.report_data_invalid",
            "reported_quote_data",
        ),
        (
            "short quoted report",
            "binding.report_data_invalid",
            "quote_report_data",
        ),
        (
            "quoted nonce",
            "binding.nonce_mismatch",
            "quote_report_data",
        ),
        (
            "quoted signer",
            "binding.report_data_mismatch",
            "signer_binding",
        ),
        (
            "signer padding",
            "binding.report_data_mismatch",
            "signer_binding",
        ),
        (
            "rtmr replay",
            "measurement.rtmr3_mismatch",
            "replay_mismatch",
        ),
        ("short rtmr", "measurement.rtmr3_mismatch", "wrong_length"),
        ("no rtmr events", "measurement.rtmr3_mismatch", "no_events"),
        (
            "invalid event JSON",
            "measurement.event_log_invalid",
            "invalid_json",
        ),
        (
            "missing event digest",
            "measurement.event_log_invalid",
            "invalid_type",
        ),
        (
            "compose hash",
            "measurement.app_compose_mrconfigid_mismatch",
            "",
        ),
        (
            "short mrconfigid",
            "measurement.mrconfigid_invalid",
            "wrong_length",
        ),
        (
            "mrconfigid version",
            "measurement.mrconfigid_invalid",
            "unsupported_version",
        ),
    ] {
        let mut quote = model_quote(TcbStatus::UpToDate);
        let mut model_attestation = model_attestation(None);
        // Reach each independent quote binding instead of only comparing the echo.
        model_attestation.reported_quote_data = None;
        match case {
            "echoed nonce" => model_attestation.evidence.nonce = "22".repeat(32),
            "debug quote" => quote.debug_enabled = true,
            "advertised report" => model_attestation.reported_quote_data = Some("00".repeat(64)),
            "short advertised report" => {
                model_attestation.reported_quote_data = Some("00".repeat(63))
            }
            "short quoted report" => {
                quote.report_data.pop();
            }
            "quoted nonce" => quote.report_data[32] ^= 1,
            "quoted signer" => quote.report_data[0] ^= 1,
            "signer padding" => quote.report_data[20] = 1,
            "rtmr replay" => quote.rt_mr3[0] ^= 1,
            "short rtmr" => {
                quote.rt_mr3.pop();
            }
            "no rtmr events" => {
                model_attestation.evidence.event_log = AttestationEventLog::Entries(vec![])
            }
            "invalid event JSON" => {
                model_attestation.evidence.event_log = AttestationEventLog::Json("[".into())
            }
            "missing event digest" => {
                model_attestation.evidence.event_log = AttestationEventLog::Json("[{}]".into())
            }
            "compose hash" => quote.mr_config_id[1] ^= 1,
            "short mrconfigid" => quote.mr_config_id.truncate(32),
            "mrconfigid version" => quote.mr_config_id[0] = 2,
            _ => unreachable!(),
        }
        let tdx_quote = FixtureTdxQuoteVerifier(quote);
        let error = verify_model_attestation(
            &model_attestation,
            &client_binding(),
            None,
            ModelAttestationVerifiers {
                tdx_quote: Some(&tdx_quote),
                deployment: Some(&UnreachableDeploymentVerifier),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), expected_code, "{case}");
        let detail = match error {
            VerificationError::NonceMismatch { binding }
            | VerificationError::ReportDataMismatch { binding } => binding,
            VerificationError::ReportDataInvalid { reason }
            | VerificationError::Rtmr3Mismatch { reason }
            | VerificationError::MrConfigIdInvalid { reason }
            | VerificationError::EventLogInvalid { reason, .. } => reason,
            _ => "",
        };
        assert_eq!(detail, expected_detail, "{case}");
    }
}

#[tokio::test]
async fn authenticates_runtime_metadata_by_recomputing_event_payload_hashes() {
    let mut replayed = vec![0; 48];
    let mut entries = vec![];
    for (event, payload) in [("os-image-hash", "aabb"), ("compose-hash", "ccdd")] {
        let mut measured = 0x0800_0001_u32.to_le_bytes().to_vec();
        measured.extend_from_slice(format!(":{event}:").as_bytes());
        measured.extend_from_slice(&hex::decode(payload).unwrap());
        let digest = sha2::Sha384::digest(measured);
        let mut extended = replayed;
        extended.extend_from_slice(&digest);
        replayed = sha2::Sha384::digest(extended).to_vec();
        entries.push(serde_json::json!({"imr": 3, "event_type": 0x0800_0001_u32,
            "event": event, "event_payload": payload, "digest": hex::encode(digest)}));
    }
    entries.push(serde_json::json!({"imr": 2, "event_type": 0x0800_0001_u32,
        "event": "os-image-hash", "event_payload": "ffff", "digest": ""}));
    let mut quote = model_quote(TcbStatus::UpToDate);
    quote.rt_mr3 = replayed;
    let tdx_quote = FixtureTdxQuoteVerifier(quote);
    for serialized in [false, true] {
        for mutation in ["none", "omitted digest", "payload", "digest"] {
            let mut entries = entries.clone();
            match mutation {
                "omitted digest" => entries[0]["digest"] = "".into(),
                "payload" => entries[0]["event_payload"] = "eeee".into(),
                "digest" => entries[0]["digest"] = "00".repeat(48).into(),
                _ => {}
            }
            let mut model_attestation = model_attestation(None);
            model_attestation.evidence.event_log = if serialized {
                AttestationEventLog::Json(serde_json::to_string(&entries).unwrap())
            } else {
                AttestationEventLog::Entries(entries)
            };
            let result = verify_model_attestation(
                &model_attestation,
                &client_binding(),
                None,
                ModelAttestationVerifiers {
                    tdx_quote: Some(&tdx_quote),
                    ..Default::default()
                },
            )
            .await;
            if mutation == "none" || mutation == "omitted digest" {
                let measurements = result.unwrap().evidence.deployment.runtime_measurements;
                assert_eq!(measurements.os_image_hash.as_deref(), Some("aabb"));
                assert_eq!(measurements.compose_hash.as_deref(), Some("ccdd"));
            } else {
                assert!(
                    matches!(
                        result,
                        Err(VerificationError::EventLogInvalid {
                            reason: "digest_mismatch",
                            ..
                        })
                    ),
                    "{mutation}, serialized={serialized}"
                );
            }
        }
    }
}

#[tokio::test]
async fn binds_normalized_public_keys_to_both_attested_signing_algorithms() {
    for algo in [SigningAlgo::Ed25519, SigningAlgo::Ecdsa] {
        let (address, public_key) = match algo {
            SigningAlgo::Ed25519 => {
                let key = hex::encode(
                    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                        .verifying_key()
                        .as_bytes(),
                );
                (key.clone(), key)
            }
            SigningAlgo::Ecdsa => {
                let key = k256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
                let point = key.verifying_key().to_sec1_point(false);
                let public = &point.as_bytes()[1..];
                (
                    hex::encode(&sha3::Keccak256::digest(public)[12..]),
                    hex::encode(public),
                )
            }
        };
        let mut quote = model_quote(TcbStatus::UpToDate);
        quote.report_data[..32].fill(0);
        let address_bytes = hex::decode(&address).unwrap();
        quote.report_data[..address_bytes.len()].copy_from_slice(&address_bytes);
        let tdx_quote = FixtureTdxQuoteVerifier(quote.clone());
        let mut valid_keys = vec![
            public_key.clone(),
            format!("0X{}", public_key.to_uppercase()),
        ];
        if algo == SigningAlgo::Ecdsa {
            valid_keys.push(format!("04{public_key}"));
        }
        for (supplied, valid) in valid_keys.into_iter().map(|key| (key, true)).chain(
            ["00".repeat(public_key.len() / 2), "00".into(), "zz".into()]
                .into_iter()
                .map(|key| (key, false)),
        ) {
            let mut model_attestation = model_attestation(None);
            model_attestation.evidence.signer.signing_algo = algo;
            model_attestation.evidence.signer.signing_address =
                format!("0X{}", address.to_uppercase());
            model_attestation.reported_quote_data = Some(hex::encode(&quote.report_data));
            model_attestation.signing_public_key = Some(supplied);
            let result = verify_model_attestation(
                &model_attestation,
                &client_binding(),
                None,
                ModelAttestationVerifiers {
                    tdx_quote: Some(&tdx_quote),
                    ..Default::default()
                },
            )
            .await;
            if valid {
                assert_eq!(
                    result.unwrap().signing_public_key.as_deref(),
                    Some(public_key.as_str())
                );
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    "binding.model_public_key_mismatch"
                );
            }
        }
    }
}
