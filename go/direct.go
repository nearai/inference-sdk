package nearai

import (
	"context"
	"reflect"
)

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
		if reflect.DeepEqual(report, *fetched.ServingAttestation) {
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

// VerifyDirectModelResponse returns all verified reports with the response's
// signer. Shared signing keys cannot identify the individual serving instance.
func VerifyDirectModelResponse(id string, request, response []byte, sig CompletionSignature, attestations []VerifiedAttestation) (VerifiedCompletionResult, error) {
	var matches []VerifiedAttestation
	if sig.Kind != "provider_tee" {
		return VerifiedCompletionResult{}, failure("signature.kind_mismatch", nil)
	}
	for _, a := range attestations {
		if a.Signer.SigningAlgo == sig.Signer.SigningAlgo && sameHex(a.Signer.SigningAddress, sig.Signer.SigningAddress) {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		return VerifiedCompletionResult{}, failure("signature.signer_mismatch", nil)
	}
	if e := VerifyModelResponse(request, response, sig, matches[0]); e != nil {
		return VerifiedCompletionResult{}, e
	}
	return VerifiedCompletionResult{CompletionID: id, SignatureKind: sig.Kind, Signature: sig, Attestations: cloneResult(AttestationVerificationResult{Models: matches}).Models}, nil
}
