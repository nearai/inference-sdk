package nearai

import (
	"bytes"
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

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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
	a := Attestation{Nonce: n, Signer: SigningIdentity{algo, signer}, IntelQuote: "ff", EventLog: events, AppCompose: compose, SigningPublicKey: hex.EncodeToString(pub)}
	return a, QuoteVerificationResult{TCBStatus: "UpToDate", ReportData: report, MRConfigID: mr, RTMR3: rtmr[:]}, priv
}
func fixedQuote(q QuoteVerificationResult) QuoteVerifier {
	return func(context.Context, string) (QuoteVerificationResult, error) { return q, nil }
}
func TestAttestationRejectsTampering(t *testing.T) {
	tests := []struct {
		name, code string
		mutate     func(*Attestation, *QuoteVerificationResult, *ClientBinding, *VerificationOptions)
	}{
		{"nonce", "binding.nonce_mismatch", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			b.Nonce = strings.Repeat("cd", 32)
		}},
		{"quote nonce", "binding.nonce_mismatch", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			q.ReportData[63] ^= 1
		}},
		{"signer", "binding.report_data_mismatch", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			q.ReportData[0] ^= 1
		}},
		{"debug", "policy.debug_enabled", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			q.DebugEnabled = true
		}},
		{"tcb", "policy.tcb_status_not_allowed", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			q.TCBStatus = "Revoked"
		}},
		{"compose", "measurement.app_compose_mrconfigid_mismatch", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			a.AppCompose += " "
		}},
		{"rtmr", "measurement.rtmr3_mismatch", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			q.RTMR3[0] ^= 1
		}},
		{"event", "measurement.event_log_invalid", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			a.EventLog = []byte(`[{"imr":3}]`)
		}},
		{"key", "binding.model_public_key_mismatch", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			a.SigningPublicKey = strings.Repeat("11", 32)
		}},
		{"gpu required", "policy.gpu_evidence_required", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			o.Policy.RequireGPUEvidence = true
		}},
		{"deployment", "provenance.verification_failed", func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
			o.DeploymentVerifier = func(context.Context, MeasuredDeployment) error { return errors.New("denied") }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, q, _ := attestationFixture(t, Ed25519)
			b := ClientBinding{Nonce: a.Nonce}
			o := VerificationOptions{}
			tt.mutate(&a, &q, &b, &o)
			o.QuoteVerifier = fixedQuote(q)
			_, e := VerifyModelAttestation(context.Background(), a, b, o)
			requireCode(t, e, tt.code)
		})
	}
}
func TestAttestationSuccessAndTLS(t *testing.T) {
	a, q, _ := attestationFixture(t, Ed25519)
	o := VerificationOptions{QuoteVerifier: fixedQuote(q)}
	v, e := VerifyModelAttestation(context.Background(), a, ClientBinding{Nonce: a.Nonce}, o)
	if e != nil || v.GPUEvidence != "not_provided" {
		t.Fatalf("%+v %v", v, e)
	}
	fp := bytes.Repeat([]byte{1}, 32)
	key, _ := unhex(a.Signer.SigningAddress)
	binding := sha256.Sum256(append(key, fp...))
	copy(q.ReportData, binding[:])
	a.SPKIFingerprint = hex.EncodeToString(fp)
	o.QuoteVerifier = fixedQuote(q)
	if _, e = VerifyGatewayAttestation(context.Background(), a, ClientBinding{a.Nonce, a.SPKIFingerprint}, o); e != nil {
		t.Fatal(e)
	}
	_, e = VerifyGatewayAttestation(context.Background(), a, ClientBinding{a.Nonce, strings.Repeat("22", 32)}, o)
	requireCode(t, e, "binding.spki_fingerprint_mismatch")
}
func TestSignaturesBindExactBytesAndKind(t *testing.T) {
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		for _, kind := range []string{"gateway", "provider_tee"} {
			t.Run(string(algo)+kind, func(t *testing.T) {
				request := []byte(`{"model":"canonical/model","messages":[]}`)
				response := []byte(`{"id":"test"}`)
				text := hashText(request) + ":" + hashText(response)
				if kind == "provider_tee" {
					text = "canonical/model:" + text
				}
				sig := CompletionSignature{Kind: kind, SignedText: text}
				if algo == Ed25519 {
					pub, priv, _ := ed25519.GenerateKey(rand.Reader)
					sig.Signer = SigningIdentity{algo, hex.EncodeToString(pub)}
					sig.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(text)))
				} else {
					priv, _ := secp.GeneratePrivateKey()
					sig.Signer = SigningIdentity{algo, hex.EncodeToString(keccak(priv.PubKey().SerializeUncompressed()[1:])[12:])}
					digest := keccak([]byte("\x19Ethereum Signed Message:\n" + itoa(len(text)) + text))
					compact := secpecdsa.SignCompact(priv, digest, false)
					sig.Signature = hex.EncodeToString(append(compact[1:], compact[0]))
				}
				verify := VerifyGatewayResponse
				if kind == "provider_tee" {
					verify = VerifyModelResponse
				}
				att := VerifiedAttestation{Signer: sig.Signer}
				if e := verify(request, response, sig, att); e != nil {
					t.Fatal(e)
				}
				requireCode(t, verify(request, append(response, ' '), sig, att), "signature.payload_mismatch")
				sig.Kind = "other"
				requireCode(t, verify(request, response, sig, att), "signature.kind_mismatch")
			})
		}
	}
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
func TestE2EEProtocolVectorsAndRoundtrip(t *testing.T) {
	seed := bytes.Repeat([]byte{11}, 32)
	hash := sha512.Sum512(seed)
	secret := hash[:32]
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64
	ecdsaSecret := make([]byte, 32)
	ecdsaSecret[31] = 1
	for _, v := range []struct {
		key              e2eeKey
		ciphertext, want string
	}{
		{e2eeKey{algo: Ed25519, secret: secret}, "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7ca0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b743d22a6968fbbdf88cd066c79b3dacd53a6991f06ce8c564e03b7eb60e2376", "fixed v2 vector"},
		{e2eeKey{algo: ECDSA, secret: ecdsaSecret}, "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a000102030405060708090a0bb70c17944e668fbe04a547595e40927c708a34b9e7c4cb5b9917a6fb2240653b2a142b86", "near-ai ecdsa vector"},
	} {
		got, e := decryptText(v.ciphertext, v.key)
		if e != nil || got != v.want {
			t.Fatalf("vector: %q %v", got, e)
		}
	}
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		key, e := newE2EEKey(algo)
		if e != nil {
			t.Fatal(e)
		}
		encrypted, e := encryptText("private 日本語", E2EEModelKey{algo, key.public})
		if e != nil {
			t.Fatal(e)
		}
		got, e := decryptText(encrypted, key)
		if e != nil || got != "private 日本語" {
			t.Fatalf("%q %v", got, e)
		}
		raw, _ := hex.DecodeString(encrypted)
		raw[len(raw)-1] ^= 1
		if _, e = decryptText(hex.EncodeToString(raw), key); e == nil {
			t.Fatal("accepted tampered AEAD")
		}
	}
}
func TestOHTTPAttestation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	config := []byte("config")
	a := OHTTPAttestation{Ed25519, hex.EncodeToString(pub), hex.EncodeToString(config), hex.EncodeToString(ed25519.Sign(priv, config))}
	if _, e := VerifyOHTTPKeyConfig(a, SigningIdentity{Ed25519, a.SigningKey}); e != nil {
		t.Fatal(e)
	}
	a.KeyConfig = "0000"
	_, e := VerifyOHTTPKeyConfig(a, SigningIdentity{Ed25519, a.SigningKey})
	requireCode(t, e, "ohttp.signature_invalid")
}
func TestDefaultQuoteVerifierRejectsMalformedQuote(t *testing.T) {
	_, e := CreateTDXQuoteVerifier("")(context.Background(), "ff")
	requireCode(t, e, "quote.verification_failed")
}
