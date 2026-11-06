package nearai

import (
	"context"
	"encoding/json"
	"net/http"
)

// InferenceClient verifies Gateway inference and owns its supported API methods.
// Always Close it when finished; verify responses after consuming their full body.
type InferenceClient struct{ *inferenceCore }

func NewInferenceClient(o InferenceOptions) (*InferenceClient, error) {
	core, err := newInferenceCore(inferenceOptions{
		ClientOptions:     o.ClientOptions,
		SigningAlgo:       o.SigningAlgo,
		E2EE:              o.E2EE,
		OHTTP:             o.OHTTP,
		AttestationTTL:    o.AttestationTTL,
		ResponseTTL:       o.ResponseTTL,
		ModelVerification: o.ModelVerification,
		DeploymentPolicy:  o.DeploymentPolicy,
	}, false,
		func(ctx context.Context, core *inferenceCore, s *session, model string) (FetchedModelAttestations, error) {
			return gatewayPreflight(ctx, core, s, model, o.GatewayVerification, o.DisableTLSBinding)
		})
	if err != nil {
		return nil, err
	}
	return &InferenceClient{inferenceCore: core}, nil
}

// HTTPClient returns an adapter that can be supplied to openai-go WithHTTPClient.
func (c *InferenceClient) HTTPClient() *http.Client {
	return &http.Client{Transport: c, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func cloneResult(r AttestationVerificationResult) AttestationVerificationResult {
	if r.Gateway != nil {
		v := cloneAttestation(*r.Gateway)
		r.Gateway = &v
	}
	r.Models = cloneAttestations(r.Models)
	return r
}

func (c *InferenceClient) Verify(ctx context.Context, model string) (AttestationVerificationResult, error) {
	s, e := c.getSession(ctx, model)
	if e != nil {
		return AttestationVerificationResult{}, e
	}
	return cloneResult(AttestationVerificationResult{Gateway: s.gateway, Models: s.models, VerifiedAt: s.verifiedAt}), nil
}

func (c *InferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedCompletionResult, error) {
	result, err := c.verifyResponse(ctx, id)
	if err != nil {
		return VerifiedCompletionResult{}, err
	}
	return VerifiedCompletionResult{
		ID: result.id, CompletionID: result.id,
		SignatureKind: result.signature.Kind, Signature: result.signature,
		Attestation: result.attestation, Attestations: result.attestations,
	}, nil
}

// CreateResponse sends a Gateway Responses request and retains its exact wire
// bytes for VerifyResponse. Use HTTPClient with openai-go for typed SSE events.
func (c *InferenceClient) CreateResponse(ctx context.Context, request any) (json.RawMessage, error) {
	return c.createJSON(ctx, "responses", request)
}

// CreateMessage sends an Anthropic Messages request and captures a Gateway receipt.
// For streaming, send POST messages with HTTPClient and consume the full body.
func (c *InferenceClient) CreateMessage(ctx context.Context, request any) (json.RawMessage, error) {
	return c.createJSON(ctx, "messages", request)
}

func gatewayPreflight(ctx context.Context, c *inferenceCore, s *session, model string, verification VerificationOptions, disableTLSBinding bool) (FetchedModelAttestations, error) {
	o := c.options
	opts := o.ModelVerification
	var fetchedModelAttestations FetchedModelAttestations
	transport := s.transport
	fetched, e := c.api.FetchGatewayAttestation(ctx, FetchOptions{SigningAlgo: o.SigningAlgo, DisableTLSBinding: disableTLSBinding})
	if e != nil {
		return FetchedModelAttestations{}, e
	}
	verified, e := VerifyGatewayAttestation(ctx, fetched.Attestation, fetched.ClientBinding, verification)
	if e != nil {
		return FetchedModelAttestations{}, e
	}
	if verified.Signer.SigningAlgo != o.SigningAlgo {
		return FetchedModelAttestations{}, failure("signature.signer_mismatch", nil)
	}
	s.gateway = &verified
	if !disableTLSBinding {
		base, ok := transport.(*http.Transport)
		if !ok {
			return FetchedModelAttestations{}, detail("api.invalid_input", "reason", "TLS pinning requires *http.Transport")
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return FetchedModelAttestations{}, failure("api.client_closed", nil)
		}
		pinned := c.transports[verified.SPKIFingerprint]
		if pinned == nil {
			pinned, e = NewPinnedTransport(base, verified.SPKIFingerprint)
			if e != nil {
				c.mu.Unlock()
				return FetchedModelAttestations{}, e
			}
			// Bound pools across Gateway key rotations. Eviction closes idle
			// sockets; sessions still holding a pool may finish normally.
			if len(c.transports) >= 16 {
				for key, old := range c.transports {
					old.CloseIdleConnections()
					delete(c.transports, key)
					break
				}
			}
			c.transports[verified.SPKIFingerprint] = pinned
		}
		c.mu.Unlock()
		s.transport = pinned
		api := *c.api
		client := *c.api.http
		client.Transport = pinned
		api.http = &client
		s.api = &api
	}
	if e := c.configureOHTTP(s, fetched.OHTTPAttestation, verified.Signer); e != nil {
		return FetchedModelAttestations{}, e
	}
	metadata, e := s.api.FetchModelMetadata(ctx, model)
	if e != nil {
		return FetchedModelAttestations{}, e
	}
	if metadata.ProviderType == "vllm" && metadata.AttestationSupported {
		fetchedModelAttestations, e = s.api.FetchModelAttestations(ctx, model, FetchOptions{SigningAlgo: o.SigningAlgo})
		if e != nil {
			return FetchedModelAttestations{}, e
		}
		if len(fetchedModelAttestations.Attestations) == 0 {
			return FetchedModelAttestations{}, failure("policy.model_attestation_required", nil)
		}
	} else if o.E2EE || o.DeploymentPolicy != nil || opts.DeploymentVerifier != nil || opts.Policy.AcceptedTCBStatuses != nil || opts.Policy.RequireGPUEvidence {
		return FetchedModelAttestations{}, failure("policy.model_attestation_required", nil)
	}
	return fetchedModelAttestations, nil
}
