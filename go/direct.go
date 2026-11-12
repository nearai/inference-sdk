package nearai

import "context"

// VerifyDirectModelAttestations checks every instance, even with shared signers.
// When reports contain TLS fingerprints, the serving report must match the peer.
func VerifyDirectModelAttestations(ctx context.Context, fetched FetchedModelAttestations, o VerificationOptions) (VerifiedDirectModelAttestations, error) {
	var out VerifiedDirectModelAttestations
	if len(fetched.Attestations) == 0 || fetched.ServingAttestation == nil {
		return out, failure("policy.model_attestation_required", nil)
	}
	serving := -1
	fingerprints := map[string]bool{}
	for i, report := range fetched.Attestations {
		if sameAttestation(report, *fetched.ServingAttestation) {
			serving = i
		}
		verified, e := VerifyDirectModelAttestation(ctx, report, fetched.ClientBinding, o)
		if e != nil {
			return VerifiedDirectModelAttestations{}, e
		}
		out.Attestations = append(out.Attestations, verified)
		if verified.SPKIFingerprint != "" && !fingerprints[verified.SPKIFingerprint] {
			out.SPKIFingerprints = append(out.SPKIFingerprints, verified.SPKIFingerprint)
			fingerprints[verified.SPKIFingerprint] = true
		}
	}
	if serving < 0 {
		return VerifiedDirectModelAttestations{}, failure("input.invalid", nil)
	}
	out.ServingAttestation = out.Attestations[serving]
	if out.ServingAttestation.SPKIFingerprint != "" && !sameHex(out.ServingAttestation.SPKIFingerprint, fetched.ClientBinding.SPKIFingerprint) {
		return VerifiedDirectModelAttestations{}, failure("binding.spki_fingerprint_mismatch", nil)
	}
	return out, nil
}

// FindDirectModelAttestationsForSignature selects all verified Direct reports
// matching the signature's signer.
func FindDirectModelAttestationsForSignature(attestations []VerifiedDirectModelAttestation, sig CompletionSignature) ([]VerifiedDirectModelAttestation, error) {
	if sig.Kind != "provider_tee" {
		return nil, failure("signature.kind_mismatch", nil)
	}
	var matches []VerifiedDirectModelAttestation
	for _, attestation := range attestations {
		if attestation.Signer.SigningAlgo == sig.Signer.SigningAlgo && sameHex(attestation.Signer.SigningAddress, sig.Signer.SigningAddress) {
			matches = append(matches, attestation)
		}
	}
	if len(matches) == 0 {
		return nil, failure("signature.signer_mismatch", nil)
	}
	return matches, nil
}

// VerifyDirectModelResponse verifies exact completion bytes and returns all
// matching verified Direct reports.
func VerifyDirectModelResponse(request, response []byte, sig CompletionSignature, attestations []VerifiedDirectModelAttestation) ([]VerifiedDirectModelAttestation, error) {
	matches, err := FindDirectModelAttestationsForSignature(attestations, sig)
	if err != nil {
		return nil, err
	}
	if err := VerifyModelResponse(request, response, sig, matches[0].VerifiedModelAttestation); err != nil {
		return nil, err
	}
	return matches, nil
}
