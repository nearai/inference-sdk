// Package nearai provides verified NEAR AI Chat Completions, including streaming,
// deployment attestation, response signatures, E2EE, and OHTTP.
package nearai

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

const DefaultBaseURL = "https://cloud-api.near.ai/v1"
const NoAliasingHeader = "X-No-Aliasing"

type SigningAlgo string

const (
	Ed25519 SigningAlgo = "ed25519"
	ECDSA   SigningAlgo = "ecdsa"
)

type SigningIdentity struct {
	SigningAlgo    SigningAlgo `json:"signingAlgo"`
	SigningAddress string      `json:"signingAddress"`
}
type Attestation struct {
	Nonce             string
	Signer            SigningIdentity
	IntelQuote        string
	EventLog          json.RawMessage
	AppCompose        string
	ReportedQuoteData string
	SigningPublicKey  string
	NvidiaPayload     *string
	SPKIFingerprint   string
	ModelName         string
	InstanceID        string
}
type ClientBinding struct{ Nonce, SPKIFingerprint string }
type OHTTPAttestation struct {
	SigningAlgo SigningAlgo `json:"signing_algo"`
	SigningKey  string      `json:"signing_key"`
	KeyConfig   string      `json:"key_config"`
	Signature   string      `json:"signature"`
}
type FetchedGatewayAttestation struct {
	Attestation      Attestation
	ClientBinding    ClientBinding
	OHTTPAttestation *OHTTPAttestation
}
type FetchedModelAttestations struct {
	Attestations       []Attestation
	ClientBinding      ClientBinding
	ServingAttestation *Attestation
	OHTTPAttestation   *OHTTPAttestation
}
type ModelMetadata struct {
	ModelID              string `json:"model_id"`
	ProviderType         string `json:"provider_type"`
	AttestationSupported bool   `json:"attestation_supported"`
}
type CompletionSignature struct {
	Kind       string          `json:"kind"`
	SignedText string          `json:"signedText"`
	Signature  string          `json:"signature"`
	Signer     SigningIdentity `json:"signer"`
}
type QuoteVerificationResult struct {
	TCBStatus                     string
	AdvisoryIDs                   []string
	DebugEnabled                  bool
	ReportData, MRConfigID, RTMR3 []byte
}
type RuntimeMeasurements struct{ OSImageHash, ComposeHash string }
type MeasuredDeployment struct {
	AppCompose          string
	RuntimeMeasurements RuntimeMeasurements
}
type AttestationPolicy struct {
	AcceptedTCBStatuses []string
	RequireGPUEvidence  bool
}
type QuoteVerifier func(context.Context, string) (QuoteVerificationResult, error)
type GPUEvidenceVerifier func(context.Context, string) error
type DeploymentVerifier func(context.Context, MeasuredDeployment) error
type VerificationOptions struct {
	Policy             AttestationPolicy
	QuoteVerifier      QuoteVerifier
	GPUVerifier        GPUEvidenceVerifier
	DeploymentVerifier DeploymentVerifier
}
type VerifiedAttestation struct {
	Signer                SigningIdentity
	TCBStatus             string
	AdvisoryIDs           []string
	Deployment            MeasuredDeployment
	DeploymentProvenance  string
	GPUEvidence           string
	SigningPublicKey      string
	SPKIFingerprint       string
	ModelName, InstanceID string
}
type AttestationVerificationResult struct {
	Gateway    *VerifiedAttestation
	Models     []VerifiedAttestation
	VerifiedAt time.Time
}
type VerifiedCompletionResult struct {
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
	Attestation   *VerifiedAttestation
	// Attestations contains every matching direct deployment; a shared key does not identify one CVM.
	Attestations []VerifiedAttestation
}

// ClientOptions configures evidence retrieval. HTTPClient is borrowed, never closed.
// A custom transport is part of the trust boundary and must perform normal TLS verification.
type ClientOptions struct {
	APIKey     string
	BaseURL    string
	Headers    http.Header
	HTTPClient *http.Client
}
type FetchOptions struct {
	SigningAlgo       SigningAlgo
	SigningAddress    string
	DisableTLSBinding bool
}

// InferenceOptions applies to Gateway and experimental direct clients. Nil TTLs
// default to one hour; a pointer to zero disables the corresponding cache.
type InferenceOptions struct {
	ClientOptions
	SigningAlgo         SigningAlgo
	E2EE                bool
	OHTTP               bool
	DisableTLSBinding   bool
	AttestationTTL      *time.Duration
	ResponseTTL         *time.Duration
	GatewayVerification VerificationOptions
	ModelVerification   VerificationOptions
	DeploymentPolicy    func(context.Context, string, MeasuredDeployment) error
	// MaxBodyBytes bounds each retained completion and request. Defaults to 64 MiB.
	MaxBodyBytes int64
}

// DirectInferenceOptions defaults E2EE to true, matching the other SDKs.
// Direct TLS identity binding is experimental and disabled in all clients.
type DirectInferenceOptions struct {
	InferenceOptions
	DisableE2EE bool
}
type VerifiedDirectModelAttestations struct {
	ServingAttestation VerifiedAttestation
	Attestations       []VerifiedAttestation
	SPKIFingerprints   []string
}
