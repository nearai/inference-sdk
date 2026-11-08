package nearai

import (
	"context"
	"testing"
)

func TestDefaultQuoteVerifierRejectsMalformedQuote(t *testing.T) {
	_, e := CreateTDXQuoteVerifier("")(context.Background(), "ff")
	requireCode(t, e, "quote.verification_failed")
}

func TestQuoteVerifierPreservesSDKError(t *testing.T) {
	a, _, _ := attestationFixture(t, Ed25519)
	original := &Error{Code: "quote.collateral_unavailable", Retryable: true}
	options := VerificationOptions{QuoteVerifier: func(context.Context, string) (QuoteVerificationResult, error) {
		return QuoteVerificationResult{}, original
	}}

	_, err := VerifyModelAttestation(context.Background(), a, ClientBinding{Nonce: a.Nonce}, options)
	if err != original {
		t.Fatalf("quote error changed: %v", err)
	}
}
