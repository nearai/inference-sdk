package nearai

import "fmt"

// Error is a structured API or verification failure. Retryable never authorizes
// replaying an inference request. Unwrap preserves cancellation and causes.
type Error struct {
	Code      string
	Details   map[string]any
	Retryable bool
	Cause     error
}

func (e *Error) Error() string               { return fmt.Sprintf("nearai: %s", e.Code) }
func (e *Error) Unwrap() error               { return e.Cause }
func failure(code string, cause error) error { return &Error{Code: code, Cause: cause} }
func detail(code, key string, value any) error {
	return &Error{Code: code, Details: map[string]any{key: value}}
}
