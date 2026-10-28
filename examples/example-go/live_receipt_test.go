//go:build e2e

package main

import (
	"context"
	"errors"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

// Retry receipt propagation only; never replay Chat or retry cryptographic failures.
func retryReceipt(ctx context.Context, check func() error) error {
	for _, delay := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 0} {
		err := check()
		if err == nil {
			return nil
		}
		var sdk *nearai.Error
		if !errors.As(err, &sdk) || (!sdk.Retryable && sdk.Code != "api.completion_signature_unavailable") || delay == 0 {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
