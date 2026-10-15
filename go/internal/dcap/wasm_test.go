//go:build !dcap_native

package dcap

import (
	"context"
	"errors"
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
