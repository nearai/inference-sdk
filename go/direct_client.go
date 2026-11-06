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

// NewDirectInferenceClient creates an experimental Direct client with attested TLS.
// E2EE is opt-in, as with NewInferenceClient.
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
	}, true, func(ctx context.Context, c *inferenceCore, s *session, model string) (FetchedModelAttestations, error) {
		return directPreflight(ctx, c, s, model, o.DisableTLSBinding)
	})
	if err != nil {
		return nil, err
	}
	return &DirectInferenceClient{inferenceCore: core}, nil
}

// Verify authenticates every returned report and the endpoint's TLS identity.
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

func directPreflight(ctx context.Context, c *inferenceCore, s *session, model string, disableTLSBinding bool) (FetchedModelAttestations, error) {
	fetched, err := c.api.FetchModelAttestations(ctx, model, FetchOptions{
		SigningAlgo: c.options.SigningAlgo, DisableTLSBinding: disableTLSBinding,
	})
	if err != nil {
		return FetchedModelAttestations{}, err
	}
	s.direct = &VerifiedDirectModelAttestations{}
	return fetched, nil
}

func (c *inferenceCore) configureDirectSession(s *session, fetched FetchedModelAttestations) error {
	s.direct.Attestations = s.models
	serving := s.direct.ServingAttestation
	if serving.SPKIFingerprint != "" {
		if !sameHex(serving.SPKIFingerprint, fetched.ClientBinding.SPKIFingerprint) {
			return failure("binding.spki_fingerprint_mismatch", nil)
		}
		var pins []string
		for _, report := range s.models {
			if !slices.Contains(s.direct.SPKIFingerprints, report.SPKIFingerprint) {
				s.direct.SPKIFingerprints = append(s.direct.SPKIFingerprints, report.SPKIFingerprint)
			}
			if report.Signer.SigningAlgo == s.selected.Signer.SigningAlgo && sameHex(report.Signer.SigningAddress, s.selected.Signer.SigningAddress) {
				pins = append(pins, report.SPKIFingerprint)
			}
		}
		if err := c.pinSession(s, pins); err != nil {
			return err
		}
	}
	return c.configureOHTTP(s, fetched.OHTTPAttestation, serving.Signer)
}
