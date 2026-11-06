package nearai

import (
	"context"
	"net/http"
	"slices"
)

// DirectInferenceClient verifies experimental Direct Chat endpoints and returns
// Direct evidence. Always Close it when finished; verify responses after consuming
// their full body.
type DirectInferenceClient struct {
	*inferenceCore
}

// NewDirectInferenceClient is experimental: no Gateway or direct TLS attestation
// binding. E2EE is opt-in, as with NewInferenceClient.
func NewDirectInferenceClient(o DirectInferenceOptions) (*DirectInferenceClient, error) {
	core, err := newInferenceCore(inferenceOptions{
		ClientOptions:     o.ClientOptions,
		SigningAlgo:       o.SigningAlgo,
		E2EE:              o.E2EE,
		OHTTP:             o.OHTTP,
		AttestationTTL:    o.AttestationTTL,
		ResponseTTL:       o.ResponseTTL,
		ModelVerification: o.ModelVerification,
		DeploymentPolicy:  o.DeploymentPolicy,
	}, true, directPreflight)
	if err != nil {
		return nil, err
	}
	return &DirectInferenceClient{inferenceCore: core}, nil
}

// Verify authenticates all reports and retains the preflight endpoint's serving
// report. Cached results keep their original VerifiedAt timestamp.
func (c *DirectInferenceClient) Verify(ctx context.Context, model string) (DirectAttestationVerificationResult, error) {
	s, err := c.getSession(ctx, model)
	if err != nil {
		return DirectAttestationVerificationResult{}, err
	}
	return DirectAttestationVerificationResult{
		VerifiedDirectModelAttestations: VerifiedDirectModelAttestations{
			ServingAttestation: s.direct.ServingAttestation,
			Attestations:       slices.Clone(s.direct.Attestations),
			SPKIFingerprints:   slices.Clone(s.direct.SPKIFingerprints),
		},
		VerifiedAt: s.verifiedAt,
	}, nil
}

// VerifyResponse authenticates the retained exact bytes and returns every
// preflight report sharing the request's selected signer.
func (c *DirectInferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedDirectCompletionResult, error) {
	result, err := c.verifyResponse(ctx, id)
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

func directPreflight(ctx context.Context, c *inferenceCore, s *session, model string) (FetchedModelAttestations, error) {
	fetched, err := c.api.FetchModelAttestations(ctx, model, FetchOptions{SigningAlgo: c.options.SigningAlgo})
	if err != nil {
		return FetchedModelAttestations{}, err
	}
	s.direct = &VerifiedDirectModelAttestations{}
	return fetched, nil
}
