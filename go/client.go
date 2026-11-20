package nearai

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
)

// HTTPClient returns an adapter that can be supplied to openai-go WithHTTPClient.
func (c *InferenceClient) HTTPClient() *http.Client {
	return &http.Client{Transport: c, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *InferenceClient) Verify(ctx context.Context, model string) (AttestationVerificationResult, error) {
	s, e := c.getSession(ctx, model)
	if e != nil {
		return AttestationVerificationResult{}, e
	}
	return AttestationVerificationResult{Gateway: new(s.gateway), Models: slices.Clone(s.models), VerifiedAt: s.verifiedAt}, nil
}

func (c *InferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedCompletionResult, error) {
	result, err := c.verifyResponse(ctx, id)
	if err != nil {
		return VerifiedCompletionResult{}, err
	}
	switch a := result.Attestation.(type) {
	case *VerifiedGatewayAttestation:
		result.Attestation = new(*a)
	case *VerifiedModelAttestation:
		result.Attestation = new(*a)
	}
	return result, nil
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

func (c *InferenceClient) gatewayPreflight(ctx context.Context, s *session, model string) (FetchedModelAttestations, error) {
	o := c.options
	opts := o.ModelVerification
	var fetchedModelAttestations FetchedModelAttestations
	bootstrap := c.api
	fetched, e := bootstrap.FetchGatewayAttestation(ctx, FetchOptions{SigningAlgo: o.SigningAlgo, DisableTLSBinding: o.DisableTLSBinding})
	if e != nil {
		return FetchedModelAttestations{}, e
	}
	verified, e := VerifyGatewayAttestation(ctx, fetched.Attestation, fetched.ClientBinding, o.GatewayVerification)
	if e != nil {
		return FetchedModelAttestations{}, e
	}
	if verified.Signer.SigningAlgo != o.SigningAlgo {
		return FetchedModelAttestations{}, failure("signature.signer_mismatch", nil)
	}
	s.gateway = verified
	if !o.DisableTLSBinding {
		if err := c.pinSession(s, verified.SPKIFingerprint); err != nil {
			return FetchedModelAttestations{}, err
		}
	}
	if e := c.configureOHTTP(s, fetched.OHTTPAttestation, verified.Signer); e != nil {
		return FetchedModelAttestations{}, e
	}
	api := s.api
	metadata, e := api.FetchModelMetadata(ctx, model)
	if e != nil {
		return FetchedModelAttestations{}, e
	}
	if metadata.ProviderType == "vllm" && metadata.AttestationSupported {
		fetchedModelAttestations, e = api.FetchModelAttestations(ctx, model, FetchOptions{SigningAlgo: o.SigningAlgo})
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
