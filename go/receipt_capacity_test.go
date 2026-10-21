package nearai

import (
	"context"
	"testing"
	"time"
)

func TestCancelledVerificationDoesNotReserveCapacity(t *testing.T) {
	f := newFakeCloud(t)
	f.signatureStarted = make(chan struct{})
	release := make(chan struct{})
	f.signatureRelease = release
	defer close(release)
	c, _ := fakeClient(t, f, func(o *InferenceOptions) { o.MaxCacheEntries = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := c.VerifyResponse(cancelled, "chat-1"); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyResponse(ctx, "chat-2"); err != nil {
		t.Fatal(err)
	}
}

func TestEvictedVerificationKeepsCapacity(t *testing.T) {
	for _, eviction := range []string{"count", "bytes", "expiry"} {
		t.Run(eviction, func(t *testing.T) {
			f := newFakeCloud(t)
			f.signatureStarted = make(chan struct{})
			release := make(chan struct{})
			f.signatureRelease = release
			c, _ := fakeClient(t, f, func(o *InferenceOptions) {
				if eviction == "count" {
					o.MaxCacheEntries = 1
				}
				if eviction == "bytes" {
					o.MaxReceiptCacheBytes = 256
				}
				if eviction == "expiry" {
					ttl := 20 * time.Millisecond
					o.ResponseTTL = &ttl
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
				t.Fatal(err)
			}
			verified := make(chan error, 1)
			go func() { _, err := c.VerifyResponse(ctx, "chat-1"); verified <- err }()
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			select {
			case <-f.signatureStarted:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if eviction == "expiry" {
				time.Sleep(40 * time.Millisecond)
			} else {
				if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
					t.Fatal(err)
				}
				_, err := c.VerifyResponse(ctx, "chat-2")
				code := "api.invalid_input"
				if eviction == "bytes" {
					code = "api.completion_not_found"
				}
				requireCode(t, err, code)
			}
			_, err := c.VerifyResponse(ctx, "chat-1")
			requireCode(t, err, "api.completion_not_found")
			close(release)
			released = true
			if err := <-verified; err != nil {
				t.Fatal(err)
			}
			if eviction != "count" {
				if _, err := c.CreateChatCompletion(ctx, chatRequest()); err != nil {
					t.Fatal(err)
				}
			}
			id := "chat-2"
			if eviction == "bytes" {
				id = "chat-3"
			}
			if _, err := c.VerifyResponse(ctx, id); err != nil {
				t.Fatal(err)
			}
		})
	}
}
