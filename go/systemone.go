package nearai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"unicode/utf8"
)

// SystemOneContent is text, a JSON object, or an array. Business validation of
// request state and criteria belongs to the server. Response numbers nested in
// structured content are json.Number values so their precision is preserved.
type SystemOneContent = any
type SystemOneQuestion struct {
	Type         string           `json:"type"`
	Instructions SystemOneContent `json:"instructions"` // Required text, object, or array.
	Criteria     any              `json:"criteria,omitempty"`
}
type SystemOneRequest struct {
	Model     string                       `json:"model"`
	State     SystemOneContent             `json:"state"`
	Questions map[string]SystemOneQuestion `json:"questions"`
}
type SystemOneAnswer struct {
	Type          string                      `json:"type"`
	Noul          *float64                    `json:"noul,omitempty"`
	Choice        *string                     `json:"choice,omitempty"`
	Score         *float64                    `json:"score,omitempty"`
	Confidence    *float64                    `json:"confidence,omitempty"`
	Probabilities map[string]float64          `json:"probabilities,omitempty"`
	Legend        map[string]SystemOneContent `json:"legend,omitempty"`
	Extra         map[string]json.RawMessage  `json:"-"`
}

// UnmarshalJSON only assigns fields of the selected variant. Future fields,
// including names belonging to another variant, remain available in Extra.
func (a *SystemOneAnswer) UnmarshalJSON(body []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return err
	}
	*a = SystemOneAnswer{}
	if err := json.Unmarshal(fields["type"], &a.Type); err != nil {
		return err
	}
	selected := map[string]any{}
	switch a.Type {
	case "noul":
		selected["noul"] = &a.Noul
	case "choice":
		selected["choice"], selected["confidence"], selected["probabilities"] = &a.Choice, &a.Confidence, &a.Probabilities
	case "score":
		selected["score"], selected["confidence"], selected["probabilities"], selected["legend"] = &a.Score, &a.Confidence, &a.Probabilities, &a.Legend
	}
	known := []string{"type"}
	for name, target := range selected {
		if raw, ok := fields[name]; ok {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			// Typed scalar fields still use float64; opaque legend content must
			// retain numeric values without converting them through float64.
			decoder.UseNumber()
			if err := decoder.Decode(target); err != nil {
				return err
			}
		}
		known = append(known, name)
	}
	a.Extra = systemOneExtras(fields, known...)
	return nil
}

type SystemOneUsage struct {
	InputTokens  uint64                     `json:"input_tokens"`
	OutputTokens uint64                     `json:"output_tokens"`
	Extra        map[string]json.RawMessage `json:"-"`
}
type SystemOneResponse struct {
	ID      *string                    `json:"id,omitempty"`
	Model   string                     `json:"model"`
	Answers map[string]SystemOneAnswer `json:"answers"`
	Usage   SystemOneUsage             `json:"usage"`
	Extra   map[string]json.RawMessage `json:"-"`
}

// SystemOneResult contains unverified output. Pass DecisionID to VerifyResponse
// before trusting Data. The receipt always uses the captured original bytes.
type SystemOneResult struct {
	Data       SystemOneResponse
	DecisionID string
}

func systemOneExtras(extra map[string]json.RawMessage, known ...string) map[string]json.RawMessage {
	for _, name := range known {
		delete(extra, name)
	}
	return extra
}

func decodeSystemOneResponse(body []byte) (SystemOneResponse, error) {
	var response SystemOneResponse
	invalid := func() (SystemOneResponse, error) {
		return SystemOneResponse{}, detail("api.invalid_response", "resource", "systemone")
	}
	if !utf8.Valid(body) || json.Unmarshal(body, &response) != nil || response.Model == "" || response.Answers == nil {
		return invalid()
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		return invalid()
	}
	var usage map[string]json.RawMessage
	if json.Unmarshal(raw["usage"], &usage) != nil || usage["input_tokens"] == nil || usage["output_tokens"] == nil || bytes.Equal(bytes.TrimSpace(usage["input_tokens"]), []byte("null")) || bytes.Equal(bytes.TrimSpace(usage["output_tokens"]), []byte("null")) {
		return invalid()
	}
	var answers map[string]json.RawMessage
	if json.Unmarshal(raw["answers"], &answers) != nil {
		return invalid()
	}
	response.Extra = systemOneExtras(raw, "id", "model", "answers", "usage")
	response.Usage.Extra = systemOneExtras(usage, "input_tokens", "output_tokens")
	probability := func(p *float64) bool { return p != nil && !math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0 && *p <= 1 }
	for key, answer := range response.Answers {
		switch answer.Type {
		case "noul":
			if !probability(answer.Noul) {
				return invalid()
			}
		case "choice", "score":
			if !probability(answer.Confidence) || answer.Probabilities == nil {
				return invalid()
			}
			// Decode values as pointers as well: JSON null must not become zero.
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(answers[key], &fields)
			var values map[string]*float64
			_ = json.Unmarshal(fields["probabilities"], &values)
			for _, value := range values {
				if !probability(value) {
					return invalid()
				}
			}
			if answer.Type == "choice" && answer.Choice == nil {
				return invalid()
			}
			if answer.Type == "score" {
				if answer.Score == nil || math.IsInf(*answer.Score, 0) || math.IsNaN(*answer.Score) || answer.Legend == nil {
					return invalid()
				}
				for _, value := range answer.Legend {
					switch value.(type) {
					case string, []any, map[string]any:
					default:
						return invalid()
					}
				}
			}
		default:
			return invalid()
		}
	}
	return response, nil
}

// CreateSystemOne sends a plaintext, nonstreaming Gateway decision once. It
// verifies attestation before sending, then retains exact bytes for VerifyResponse.
func (c *InferenceClient) CreateSystemOne(ctx context.Context, request any) (SystemOneResult, error) {
	return c.CreateSystemOneWithHeaders(ctx, request, nil)
}

// CreateSystemOneWithHeaders adds per-call headers while preserving client-owned
// authentication and the generated body's identity encoding and integrity headers.
func (c *InferenceClient) CreateSystemOneWithHeaders(ctx context.Context, request any, headers http.Header) (SystemOneResult, error) {
	generation := c.responseCacheGeneration()
	var result SystemOneResult
	if c.api.direct || c.options.E2EE || c.options.OHTTP {
		return result, detail("api.invalid_input", "resource", "systemone")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return result, failure("api.invalid_input", err)
	}
	parsed, err := decodeObject(body)
	if err != nil {
		return result, failure("api.invalid_input", err)
	}
	model, ok := parsed["model"].(string)
	_, stream := parsed["stream"]
	if !ok || model == "" || stream {
		return result, detail("api.invalid_input", "resource", "systemone")
	}
	s, err := c.getSession(ctx, model)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer cancel()
	defer stop()
	req, err := http.NewRequestWithContext(ctx, "POST", c.api.endpoint("systemone", nil), bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	// System One is dispatched once, even when callers supply an idempotency
	// header. Prevent the standard transport from replaying this nonempty body
	// after a failure on a reused connection.
	req.GetBody = nil
	req.Header = c.api.headers.Clone()
	for k, v := range headers {
		req.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	for _, name := range []string{"Authorization", "Api-Key"} {
		req.Header.Del(name)
		for _, value := range c.api.headers.Values(name) {
			req.Header.Add(name, value)
		}
	}
	removeE2EEHeaders(req.Header)
	if s.selected != nil {
		req.Header.Set("X-Model-Pub-Key", s.selected.SigningPublicKey)
	}
	removeBodyHeaders(req.Header)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(NoAliasingHeader, "true")
	res, err := s.transport.RoundTrip(req)
	if err != nil {
		return result, &Error{Code: "api.transport_failed", Details: map[string]any{"resource": "systemone", "reason": "request"}, Cause: err}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return result, &Error{Code: "api.http_status", Details: map[string]any{"resource": "systemone", "status": res.StatusCode}}
	}
	id := res.Header.Get("X-Generation-Id")
	if id == "" {
		return result, detail("api.invalid_response", "resource", "systemone.x-generation-id")
	}
	if err := decodeResponse(res); err != nil {
		return result, &Error{Code: "api.transport_failed", Details: map[string]any{"resource": "systemone", "reason": "response_body"}, Cause: err}
	}
	wire, err := io.ReadAll(res.Body)
	if err != nil {
		var sdk *Error
		if errors.As(err, &sdk) {
			return result, err
		}
		return result, &Error{Code: "api.transport_failed", Details: map[string]any{"resource": "systemone", "reason": "response_body"}, Cause: err}
	}
	data, err := decodeSystemOneResponse(wire)
	if err != nil {
		return result, err
	}
	if err = c.register(id, body, wire, s, false, generation); err != nil {
		return result, err
	}
	return SystemOneResult{Data: data, DecisionID: id}, nil
}
