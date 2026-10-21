package demo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

func TestOversizedRetryAfterRemainsCancellable(t *testing.T) {
	wait := rateLimitDelay(strings.Repeat("9", 400), time.Now())
	if wait <= 180*time.Second {
		t.Fatalf("oversized Retry-After fell back to %v", wait)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepRateLimit(ctx, wait); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait did not cancel: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestOpenAILiveRateLimitBudget(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, exhausted := range []bool{false, true} {
			name := "json"
			if streaming {
				name = "stream"
			}
			if exhausted {
				name += "-exhausted"
			}
			t.Run(name, func(t *testing.T) {
				calls := 0
				var waits []time.Duration
				var firstBody string
				var rejected []*trackedBody
				transport := &rateLimitTransport{
					base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
						calls++
						body, err := io.ReadAll(request.Body)
						request.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
						if calls == 1 {
							firstBody = string(body)
						}
						if string(body) != firstBody {
							t.Fatal("replayed request changed")
						}
						headers := http.Header{"Content-Type": {"application/json"}}
						status := 200
						payload := `{"id":"json","choices":[{"message":{"content":"answer"}}]}`
						if calls < 4 || exhausted {
							status = 429
							payload = `{"error":{"message":"rate limited","type":"rate_limit"}}`
						} else if streaming {
							headers.Set("Content-Type", "text/event-stream")
							payload = "data: {\"id\":\"stream\",\"choices\":[{\"delta\":{\"content\":\"answer\"}}]}\n\ndata: [DONE]\n\n"
						}
						responseBody := &trackedBody{Reader: strings.NewReader(payload)}
						if status == 429 {
							rejected = append(rejected, responseBody)
						}
						return &http.Response{StatusCode: status, Header: headers, Body: responseBody, Request: request}, nil
					}),
					sleep: func(_ context.Context, delay time.Duration) error {
						waits = append(waits, delay)
						return nil
					},
				}
				client := openai.NewClient(option.WithAPIKey("test"), option.WithBaseURL("https://example.test/v1/"), option.WithMaxRetries(0), option.WithHTTPClient(&http.Client{Transport: transport}))
				params := openai.ChatCompletionNewParams{Model: "m", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hello")}}
				var err error
				if streaming {
					stream := client.Chat.Completions.NewStreaming(context.Background(), params)
					for stream.Next() {
					}
					err = stream.Err()
					stream.Close()
				} else {
					_, err = client.Chat.Completions.New(context.Background(), params)
				}
				if exhausted {
					var apiError *openai.Error
					if !errors.As(err, &apiError) || apiError.StatusCode != 429 {
						t.Fatalf("expected final 429, got %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if calls != 4 || !reflect.DeepEqual(waits, []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}) {
					t.Fatalf("calls=%d waits=%v", calls, waits)
				}
				for _, body := range rejected {
					if !body.closed {
						t.Fatal("rate-limited response was not closed")
					}
				}
			})
		}
	}
}

func TestLiveRateLimitRetryAfterAndCancellation(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	for _, hint := range []string{"30", now.Add(30 * time.Second).Format(http.TimeFormat)} {
		if delay := rateLimitDelay(hint, now); delay != 30*time.Second {
			t.Fatalf("%q: %v", hint, delay)
		}
	}
	for _, hint := range []string{"-1", "invalid", "9999999999999999999999999x"} {
		if delay := rateLimitDelay(hint, now); delay != 0 {
			t.Fatalf("%q: %v", hint, delay)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	responseBody := &trackedBody{Reader: strings.NewReader("limited")}
	transport := &rateLimitTransport{
		base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			request.Body.Close()
			return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"30"}}, Body: responseBody}, nil
		}),
		sleep: func(ctx context.Context, delay time.Duration) error {
			if delay != 30*time.Second {
				t.Fatalf("ignored Retry-After: %v", delay)
			}
			cancel()
			return sleepRateLimit(ctx, delay)
		},
	}
	request, _ := http.NewRequestWithContext(ctx, "POST", "https://example.test/v1/chat/completions", strings.NewReader("{}"))
	_, err := transport.RoundTrip(request)
	if !errors.Is(err, context.Canceled) || calls != 1 || !responseBody.closed {
		t.Fatalf("calls=%d err=%v closed=%v", calls, err, responseBody.closed)
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (brokenBody) Close() error             { return nil }

func TestLiveRateLimitDoesNotReplayOtherFailures(t *testing.T) {
	for _, scenario := range []string{"http500", "network", "json-body", "stream-body"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			transport := &rateLimitTransport{
				base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					request.Body.Close()
					if scenario == "network" {
						return nil, io.ErrUnexpectedEOF
					}
					response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: brokenBody{}, Request: request}
					if scenario == "http500" {
						response.StatusCode = 500
						response.Body = io.NopCloser(strings.NewReader(`{"error":{"message":"unavailable"}}`))
					}
					if scenario == "stream-body" {
						response.Header.Set("Content-Type", "text/event-stream")
					}
					return response, nil
				}),
				sleep: func(context.Context, time.Duration) error { t.Fatal("unexpected retry"); return nil },
			}
			client := openai.NewClient(option.WithAPIKey("test"), option.WithBaseURL("https://example.test/v1/"), option.WithMaxRetries(0), option.WithHTTPClient(&http.Client{Transport: transport}))
			params := openai.ChatCompletionNewParams{Model: "m", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hello")}}
			var err error
			if scenario == "stream-body" {
				stream := client.Chat.Completions.NewStreaming(context.Background(), params)
				for stream.Next() {
				}
				err = stream.Err()
				stream.Close()
			} else {
				_, err = client.Chat.Completions.New(context.Background(), params)
			}
			if err == nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}
