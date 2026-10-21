package e2e

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestRetryBudgetAndBodyLifecycle(t *testing.T) {
	for _, statuses := range [][]int{{429, 429, 429, 429}, {429, 200}, {503}, {200}} {
		calls := 0
		var bodies []*trackedBody
		var waits []time.Duration
		response, err := retryChat(context.Background(), func() (*http.Response, error) {
			status := statuses[calls]
			calls++
			body := &trackedBody{Reader: strings.NewReader("response")}
			bodies = append(bodies, body)
			return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"12"}}, Body: body}, nil
		}, func(_ context.Context, wait time.Duration) error {
			if !bodies[len(bodies)-1].closed {
				t.Fatal("429 body must close before sleep")
			}
			waits = append(waits, wait)
			return nil
		})
		if err != nil || calls != len(statuses) || response.StatusCode != statuses[len(statuses)-1] {
			t.Fatalf("calls=%d response=%v err=%v", calls, response, err)
		}
		if bodies[len(bodies)-1].closed {
			t.Fatal("final response must remain readable")
		}
		want := []time.Duration{12 * time.Second, 12 * time.Second, 20 * time.Second}[:len(statuses)-1]
		if len(want) > 0 && !reflect.DeepEqual(waits, want) {
			t.Fatalf("waits=%v want=%v", waits, want)
		}
		response.Body.Close()
	}
}

func TestOHTTPAndCancellation(t *testing.T) {
	for _, status := range []int{429, 503} {
		calls := 0
		cause := &nearai.Error{Code: "api.http_status", Details: map[string]any{"resource": "ohttp", "status": status, "retryAfter": "12"}}
		_, err := retryChat(context.Background(), func() (*http.Response, error) { calls++; return nil, cause }, func(_ context.Context, d time.Duration) error {
			if d < 12*time.Second {
				t.Fatal(d)
			}
			return nil
		})
		expected := 1
		if status == 429 {
			expected = 4
		}
		if err != cause || calls != expected {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := retryChat(ctx, func() (*http.Response, error) { t.Fatal("must not send"); return nil, nil }, sleepContext)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRetryAfter(t *testing.T) {
	at, _ := http.ParseTime("Wed, 21 Oct 2015 07:28:00 GMT")
	if retryAfterDelay(at.Format(http.TimeFormat), at.Add(-30*time.Second)) != 30*time.Second || retryAfterDelay("30", at) != 30*time.Second || retryAfterDelay("invalid", at) != 0 {
		t.Fatal("retry-after parsing")
	}
}

func TestOversizedRetryAfterWaitsForCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := retryChat(ctx, func() (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": {strings.Repeat("9", 400)}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}, func(ctx context.Context, wait time.Duration) error {
		if wait <= 180*time.Second {
			t.Fatalf("oversized Retry-After fell back to %v", wait)
		}
		cancel()
		return sleepContext(ctx, wait)
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
