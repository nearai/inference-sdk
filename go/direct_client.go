package nearai

import (
	"context"
	"encoding/json"
	"net/http"
)

// DirectInferenceClient verifies experimental Direct Chat endpoints. It shares
// transport and cache behavior with InferenceClient, but returns Direct evidence
// and does not expose Gateway-only APIs. Always Close it when finished.
type DirectInferenceClient struct {
	client *InferenceClient
}

// NewDirectInferenceClient is experimental: no Gateway or direct TLS attestation
// binding. E2EE is opt-in, as with NewInferenceClient.
func NewDirectInferenceClient(o DirectInferenceOptions) (*DirectInferenceClient, error) {
	if o.DisableE2EE {
		o.E2EE = false
	}
	client, err := newInferenceClient(o.InferenceOptions, true)
	if err != nil {
		return nil, err
	}
	return &DirectInferenceClient{client: client}, nil
}

// Verify authenticates all reports and retains the preflight endpoint's serving
// report. Cached results keep their original VerifiedAt timestamp.
func (c *DirectInferenceClient) Verify(ctx context.Context, model string) (DirectAttestationVerificationResult, error) {
	s, err := c.client.getSession(ctx, model)
	if err != nil {
		return DirectAttestationVerificationResult{}, err
	}
	return DirectAttestationVerificationResult{
		VerifiedDirectModelAttestations: VerifiedDirectModelAttestations{
			ServingAttestation: cloneAttestation(s.direct.ServingAttestation),
			Attestations:       cloneAttestations(s.direct.Attestations),
			SPKIFingerprints:   append([]string(nil), s.direct.SPKIFingerprints...),
		},
		VerifiedAt: s.result.VerifiedAt,
	}, nil
}

// VerifyResponse authenticates the retained exact bytes and returns every
// preflight report sharing the request's selected signer.
func (c *DirectInferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedDirectCompletionResult, error) {
	result, err := c.client.verifyResponse(ctx, id)
	if err != nil {
		return VerifiedDirectCompletionResult{}, err
	}
	return VerifiedDirectCompletionResult{
		ID: result.id, CompletionID: result.id,
		SignatureKind: result.signature.Kind, Signature: result.signature,
		Attestations: result.attestations,
	}, nil
}

// HTTPClient returns the verified transport for the official OpenAI client.
func (c *DirectInferenceClient) HTTPClient() *http.Client {
	return &http.Client{Transport: c, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *DirectInferenceClient) BaseURL() string { return c.client.BaseURL() }

// RoundTrip accepts POSTs to the configured Direct Chat Completions endpoint.
func (c *DirectInferenceClient) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.client.RoundTrip(req)
}

// CreateChatCompletion sends JSON Chat. Use HTTPClient for streaming requests.
func (c *DirectInferenceClient) CreateChatCompletion(ctx context.Context, request any) (json.RawMessage, error) {
	return c.client.CreateChatCompletion(ctx, request)
}

// ClearResponseCache releases captured responses while keeping the client reusable.
func (c *DirectInferenceClient) ClearResponseCache() { c.client.ClearResponseCache() }

func (c *DirectInferenceClient) Close() error { return c.client.Close() }
