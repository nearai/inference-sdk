// Shared, bounded retry budget for rejected live Chat requests.
package e2e

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	nearai "github.com/nearai/inference-sdk/go"
)

func sendChatWithRetry(ctx context.Context, client *http.Client, request *http.Request) (*http.Response, error) {
	return retryChat(ctx, func() (*http.Response, error) {
		next := request.Clone(ctx)
		if request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return nil, err
			}
			next.Body = body
		}
		return client.Do(next)
	}, sleepContext)
}

func retryChat(ctx context.Context, send func() (*http.Response, error), sleep func(context.Context, time.Duration) error) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := send()
		hint := ""
		if err != nil {
			var sdk *nearai.Error
			if !errors.As(err, &sdk) || sdk.Code != "api.http_status" || sdk.Details["resource"] != "ohttp" || sdk.Details["status"] != http.StatusTooManyRequests || attempt == 3 {
				return response, err
			}
			hint, _ = sdk.Details["retryAfter"].(string)
		} else {
			if response.StatusCode != http.StatusTooManyRequests || attempt == 3 {
				return response, nil
			}
			hint = response.Header.Get("Retry-After")
			response.Body.Close()
		}
		delay := time.Duration(5<<attempt) * time.Second
		if requested := retryAfterDelay(hint, time.Now()); requested > delay {
			delay = requested
		}
		if err := sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

func retryAfterDelay(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value != "" && strings.Trim(value, "0123456789") == "" {
		// ParseUint saturates at 32 bits, which still fits in a duration.
		seconds, _ := strconv.ParseUint(value, 10, 32)
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
