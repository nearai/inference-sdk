package nearai

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func requireCode(t *testing.T, e error, code string) {
	t.Helper()
	var failure *Error
	if !errors.As(e, &failure) || failure.Code != code {
		t.Fatalf("want %s, got %v", code, e)
	}
}
func attestationFixture(t *testing.T, algo SigningAlgo) (Attestation, QuoteVerificationResult, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer := hex.EncodeToString(pub)
	if algo == ECDSA {
		signer = strings.Repeat("11", 20)
	}
	n := strings.Repeat("ab", 32)
	address, _ := unhex(signer)
	nb, _ := unhex(n)
	report := make([]byte, 64)
	copy(report, address)
	copy(report[32:], nb)
	compose := `{"docker_compose_file":"services: {}"}`
	hash := sha256.Sum256([]byte(compose))
	mr := make([]byte, 48)
	mr[0] = 1
	copy(mr[1:], hash[:])
	digest := sha512.Sum384([]byte("measured event"))
	rtmr := sha512.Sum384(append(make([]byte, 48), digest[:]...))
	events, _ := json.Marshal([]map[string]any{{"imr": 3, "digest": hex.EncodeToString(digest[:])}})
	a := Attestation{
		Nonce:            n,
		Signer:           SigningIdentity{algo, signer},
		IntelQuote:       "ff",
		EventLog:         events,
		AppCompose:       compose,
		SigningPublicKey: hex.EncodeToString(pub),
	}
	return a, QuoteVerificationResult{TCBStatus: "UpToDate", ReportData: report, MRConfigID: mr, RTMR3: rtmr[:]}, priv
}
func fixedQuote(q QuoteVerificationResult) QuoteVerifier {
	return func(context.Context, string) (QuoteVerificationResult, error) { return q, nil }
}
