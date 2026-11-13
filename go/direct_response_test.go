package nearai

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectsTheCompleteDirectSignerGroup(t *testing.T) {
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		t.Run(string(algo), func(t *testing.T) {
			length, otherAlgo := 32, ECDSA
			if algo == ECDSA {
				length, otherAlgo = 20, Ed25519
			}
			signer := SigningIdentity{SigningAlgo: algo, SigningAddress: strings.Repeat("ab", length)}
			first := VerifiedDirectModelAttestation{
				VerifiedModelAttestation: VerifiedModelAttestation{VerifiedAttestationEvidence: VerifiedAttestationEvidence{Signer: signer}},
				ModelName:                "test-model", InstanceID: "first", SPKIFingerprint: strings.Repeat("11", 32),
			}
			second := first
			second.Signer.SigningAddress = "0X" + strings.Repeat("AB", length)
			second.InstanceID, second.SPKIFingerprint = "second", strings.Repeat("22", 32)
			other := first
			other.Signer.SigningAddress = strings.Repeat("cd", length)
			signature := CompletionSignature{Kind: "provider_tee", Signer: signer}
			attestations := []VerifiedDirectModelAttestation{other, first, second}
			matching, err := FindDirectModelAttestationsForSignature(attestations, signature)
			if err != nil || !reflect.DeepEqual(matching, attestations[1:]) {
				t.Fatalf("signer group: %v %v", matching, err)
			}
			_, err = FindDirectModelAttestationsForSignature(attestations[:1], signature)
			requireCode(t, err, "signature.signer_mismatch")
			signature.Kind = "gateway"
			_, err = FindDirectModelAttestationsForSignature(attestations, signature)
			requireCode(t, err, "signature.kind_mismatch")
			signature.Kind = "provider_tee"
			signature.Signer.SigningAlgo = otherAlgo
			_, err = FindDirectModelAttestationsForSignature(attestations, signature)
			requireCode(t, err, "signature.signer_mismatch")
		})
	}
}
