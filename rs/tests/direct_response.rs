mod support;

use nearai_inference_sdk::{
    find_direct_model_attestations_for_signature, CompletionSignature, CompletionSignatureKind,
    SigningAlgo, SigningIdentity, VerificationError, VerifiedDirectModelAttestation,
};

#[test]
fn selects_the_complete_direct_signer_group() {
    for (signing_algo, length) in [(SigningAlgo::Ed25519, 32), (SigningAlgo::Ecdsa, 20)] {
        let signer = SigningIdentity {
            signing_algo,
            signing_address: "ab".repeat(length),
        };
        let first = VerifiedDirectModelAttestation {
            attestation: support::verified_model_attestation(signer.clone()),
            model_name: "test-model".into(),
            instance_id: Some("first".into()),
            spki_fingerprint: Some("11".repeat(32)),
        };
        let mut second = first.clone();
        second.attestation.evidence.signer.signing_address = format!("0X{}", "AB".repeat(length));
        second.instance_id = Some("second".into());
        second.spki_fingerprint = Some("22".repeat(32));
        let mut other = first.clone();
        other.attestation.evidence.signer.signing_address = "cd".repeat(length);
        let mut signature = CompletionSignature {
            kind: CompletionSignatureKind::ProviderTee,
            signer,
            signed_text: String::new(),
            signature: String::new(),
        };
        let attestations = [other, first, second];
        let matching =
            find_direct_model_attestations_for_signature(&attestations, &signature).unwrap();
        assert_eq!(matching.len(), 2);
        assert!(std::ptr::eq(matching[0], &attestations[1]));
        assert!(std::ptr::eq(matching[1], &attestations[2]));
        assert!(matches!(
            find_direct_model_attestations_for_signature(&attestations[..1], &signature),
            Err(VerificationError::SignatureSignerMismatch)
        ));
        signature.kind = CompletionSignatureKind::Gateway;
        assert!(matches!(
            find_direct_model_attestations_for_signature(&attestations, &signature),
            Err(VerificationError::SignatureKindMismatch { .. })
        ));
        signature.kind = CompletionSignatureKind::ProviderTee;
        signature.signer.signing_algo = match signing_algo {
            SigningAlgo::Ed25519 => SigningAlgo::Ecdsa,
            SigningAlgo::Ecdsa => SigningAlgo::Ed25519,
        };
        assert!(matches!(
            find_direct_model_attestations_for_signature(&attestations, &signature),
            Err(VerificationError::SignatureSignerMismatch)
        ));
    }
}
