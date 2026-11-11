//go:build !dcap_native

package dcap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWASMDeadlineInterruptsVerification(t *testing.T) {
	quote, collateral, now := offlineFixture(t)
	// Compile and warm the code cache before testing guest execution cancellation.
	if _, err := Verify(quote, collateral, now); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := VerifyContext(ctx, quote, collateral, now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline did not interrupt guest: %v", err)
	}

	// Closing one guest must not invalidate shared compiled code or other calls.
	if _, err := Verify(quote, collateral, now); err != nil {
		t.Fatal(err)
	}
}

func TestCollateralSignerMustBeIssuedByRoot(t *testing.T) {
	quote, collateral, now := offlineFixture(t)
	parsed, err := ParseQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CertChainPEM == "" {
		t.Fatal("fixture has no PCK certificate chain")
	}

	// Match the upstream regression: a PCK leaf chains through an intermediate
	// CA, so it must be rejected as a collateral signer before signature checks.
	for _, signer := range []string{"TCB Info", "QE Identity"} {
		t.Run(signer, func(t *testing.T) {
			forged := *collateral
			if signer == "TCB Info" {
				forged.TCBInfoIssuerChain = parsed.CertChainPEM
			} else {
				forged.QEIdentityIssuerChain = parsed.CertChainPEM
			}
			_, err := Verify(quote, &forged, now)
			want := signer + " signer must be issued directly by the root CA"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected root-issued signer validation %q, got %v", want, err)
			}
		})
	}
}
