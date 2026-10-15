package demo

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Only the live runner installs this wrapper, outside the verified transport.
// Retry rejected request starts; successful response bodies and streams are never replayed.
type rateLimitTransport struct {
	base  http.RoundTripper
	sleep func(context.Context, time.Duration) error
}

func (t *rateLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/chat/completions") {
		return t.base.RoundTrip(request)
	}
	ctx := request.Context()
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if request.Body != nil {
				request.Body.Close()
			}
			return nil, err
		}
		response, err := t.base.RoundTrip(request)
		if err != nil || response.StatusCode != http.StatusTooManyRequests || attempt == 3 || request.GetBody == nil {
			return response, err
		}
		delay := time.Duration(5<<attempt) * time.Second
		if requested := rateLimitDelay(response.Header.Get("Retry-After"), time.Now()); requested > delay {
			delay = requested
		}
		response.Body.Close()
		if err := t.sleep(ctx, delay); err != nil {
			return nil, err
		}
		next := request.Clone(ctx)
		next.Body, err = request.GetBody()
		if err != nil {
			return nil, err
		}
		request = next
	}
}

func rateLimitDelay(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

func sleepRateLimit(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
