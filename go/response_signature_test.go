package nearai

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

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
					digest := keccak([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(text)) + text))
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
				requireCode(t, verify(append(request, ' '), response, sig, att), "signature.payload_mismatch")
				for _, scenario := range []struct {
					name, code string
					mutate     func(*CompletionSignature)
				}{
					{"kind", "signature.kind_mismatch", func(s *CompletionSignature) { s.Kind = "other" }},
					{"signer", "signature.signer_mismatch", func(s *CompletionSignature) {
						s.Signer.SigningAddress = strings.Repeat("11", len(s.Signer.SigningAddress)/2)
					}},
					{"algorithm", "signature.signer_mismatch", func(s *CompletionSignature) {
						if s.Signer.SigningAlgo == Ed25519 {
							s.Signer.SigningAlgo = ECDSA
						} else {
							s.Signer.SigningAlgo = Ed25519
						}
					}},
					{"signature", "signature.invalid", func(s *CompletionSignature) {
						raw, err := hex.DecodeString(s.Signature)
						if err != nil {
							t.Fatal(err)
						}
						raw[0] ^= 1
						s.Signature = hex.EncodeToString(raw)
					}},
				} {
					t.Run(scenario.name, func(t *testing.T) {
						mutated := sig
						scenario.mutate(&mutated)
						requireCode(t, verify(request, response, mutated, att), scenario.code)
					})
				}
			})
		}
	}
}
