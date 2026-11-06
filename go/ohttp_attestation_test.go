package nearai

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOHTTPAttestation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	config := []byte("config")
	a := OHTTPAttestation{
		Ed25519,
		hex.EncodeToString(pub),
		hex.EncodeToString(config),
		hex.EncodeToString(ed25519.Sign(priv, config)),
	}
	signer := SigningIdentity{Ed25519, a.SigningKey}
	verified, err := VerifyOHTTPKeyConfig(a, signer)
	if err != nil || !bytes.Equal(verified, config) {
		t.Fatalf("authenticated config = %x, %v", verified, err)
	}
	for _, scenario := range []struct {
		name, code string
		mutate     func(*OHTTPAttestation, *SigningIdentity)
	}{
		{"config bytes", "ohttp.signature_invalid", func(a *OHTTPAttestation, _ *SigningIdentity) { a.KeyConfig = "0000" }},
		{"signature bytes", "ohttp.signature_invalid", func(a *OHTTPAttestation, _ *SigningIdentity) { a.Signature = strings.Repeat("00", 64) }},
		{"unverified signer", "ohttp.signer_mismatch", func(_ *OHTTPAttestation, s *SigningIdentity) { s.SigningAddress = strings.Repeat("22", 32) }},
		{"unsupported algorithm", "ohttp.signer_mismatch", func(a *OHTTPAttestation, _ *SigningIdentity) { a.SigningAlgo = ECDSA }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			modified, identity := a, signer
			scenario.mutate(&modified, &identity)
			_, err := VerifyOHTTPKeyConfig(modified, identity)
			requireCode(t, err, scenario.code)
		})
	}
}
