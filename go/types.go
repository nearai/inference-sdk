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
	ComposeManagerAttestation *ComposeManagerAttestation
	Nonce                     string
	Signer                    SigningIdentity
	IntelQuote                string
	EventLog                  json.RawMessage
	AppCompose                string
	ReportedQuoteData         string
	SigningPublicKey          string
	NvidiaPayload             *string
	SPKIFingerprint           string
	ModelName                 string
	InstanceID                string
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
	ComposeManager      *VerifiedComposeManagerAttestation
	AppCompose          string
	RuntimeMeasurements RuntimeMeasurements
}
type AttestationPolicy struct {
	AcceptedTCBStatuses []string
	RequireGPUEvidence  bool
}
type QuoteVerifier func(context.Context, string) (QuoteVerificationResult, error)
type GPUEvidenceVerifier func(context.Context, string) error

// DeploymentVerifier inspects read-only evidence and returns an error to reject it.
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

// AttestationVerificationResult contains Gateway preflight evidence.
type AttestationVerificationResult struct {
	Gateway    *VerifiedAttestation
	Models     []VerifiedAttestation
	VerifiedAt time.Time
}

// VerifiedCompletionResult contains a response receipt verified by a Gateway client.
type VerifiedCompletionResult struct {
	ID string
	// Deprecated: use ID. CompletionID contains the same value.
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
	// Attestation contains Gateway evidence for gateway receipts.
	// For provider_tee receipts it retains the report used to select the request's
	// model public key; it does not identify which instance served the request.
	//
	// Reading this field for provider_tee receipts is deprecated: use Attestations
	// for all verified reports sharing the selected signer. Gateway receipts
	// continue to use Attestation.
	Attestation *VerifiedAttestation
	// Attestations contains every matching verified model deployment for provider_tee
	// receipts. A shared key does not identify one CVM. It is empty for Gateway receipts.
	Attestations []VerifiedAttestation
}

// ClientOptions configures evidence retrieval. HTTPClient is borrowed, never closed.
// A custom transport is part of the trust boundary and must perform normal TLS verification.
type ClientOptions struct {
	// API Key is optional. Gateway and direct reports omit authentication;
	// model reports through the Gateway use it for organization access.
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

// InferenceOptions configures Gateway inference. Nil TTLs
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
}

// DirectInferenceOptions leaves E2EE disabled by default.
// Direct TLS identity binding is experimental and disabled in all clients.
type DirectInferenceOptions struct {
	ClientOptions
	SigningAlgo       SigningAlgo
	E2EE              bool
	OHTTP             bool
	AttestationTTL    *time.Duration
	ResponseTTL       *time.Duration
	ModelVerification VerificationOptions
	DeploymentPolicy  func(context.Context, string, MeasuredDeployment) error

	// Deprecated: E2EE is disabled by default. Set E2EE to enable it.
	// When true, DisableE2EE takes precedence over E2EE.
	DisableE2EE bool
}
type VerifiedDirectModelAttestations struct {
	ServingAttestation VerifiedAttestation
	Attestations       []VerifiedAttestation
	SPKIFingerprints   []string
}

// DirectAttestationVerificationResult contains every verified Direct report.
// ServingAttestation is the report returned by the preflight endpoint; it does
// not identify which instance serves a later completion. Direct TLS binding
// remains disabled, so SPKIFingerprints is empty.
type DirectAttestationVerificationResult struct {
	VerifiedDirectModelAttestations
	VerifiedAt time.Time
}

// VerifiedDirectCompletionResult contains the complete preflight-verified signer
// group for a Direct receipt. A shared signer does not identify one instance.
type VerifiedDirectCompletionResult struct {
	ID string
	// Deprecated: use ID. CompletionID contains the same value.
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
	Attestations  []VerifiedAttestation
}
