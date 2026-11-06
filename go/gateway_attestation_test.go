package nearai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGatewayAttestationTLSBinding(t *testing.T) {
	a, q, _ := attestationFixture(t, Ed25519)
	o := VerificationOptions{}
	fp := bytes.Repeat([]byte{1}, 32)
	key, _ := unhex(a.Signer.SigningAddress)
	binding := sha256.Sum256(append(key, fp...))
	copy(q.ReportData, binding[:])
	a.SPKIFingerprint = hex.EncodeToString(fp)
	o.QuoteVerifier = fixedQuote(q)
	if _, e := VerifyGatewayAttestation(context.Background(), a, ClientBinding{a.Nonce, a.SPKIFingerprint}, o); e != nil {
		t.Fatal(e)
	}
	_, e := VerifyGatewayAttestation(context.Background(), a, ClientBinding{a.Nonce, strings.Repeat("22", 32)}, o)
	requireCode(t, e, "binding.spki_fingerprint_mismatch")
}
