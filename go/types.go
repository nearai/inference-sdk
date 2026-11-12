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

// DeploymentVerifier applies deployment policy and returns an error to reject it.
type DeploymentVerifier func(context.Context, MeasuredDeployment) error
type VerificationOptions struct {
	Policy             AttestationPolicy
	QuoteVerifier      QuoteVerifier
	GPUVerifier        GPUEvidenceVerifier
	DeploymentVerifier DeploymentVerifier
}

// VerifiedAttestationEvidence contains verified signer and deployment evidence.
type VerifiedAttestationEvidence struct {
	Signer               SigningIdentity
	TCBStatus            string
	AdvisoryIDs          []string
	Deployment           MeasuredDeployment
	DeploymentProvenance string
}

type VerifiedModelAttestation struct {
	VerifiedAttestationEvidence
	Report           *Attestation
	GPUEvidence      string
	SigningPublicKey string
}

type VerifiedGatewayAttestation struct {
	VerifiedAttestationEvidence
	Report          *Attestation
	SPKIFingerprint string
}

type VerifiedDirectModelAttestation struct {
	VerifiedModelAttestation
	ModelName, InstanceID string
	SPKIFingerprint       string
}

// AttestationVerificationResult contains Gateway preflight evidence.
type AttestationVerificationResult struct {
	Gateway    *VerifiedGatewayAttestation
	Models     []VerifiedModelAttestation
	VerifiedAt time.Time
}

// VerifiedCompletionAttestation is Gateway evidence or a model representative.
// Model receipts expose all matching reports in VerifiedCompletionResult.Attestations.
type VerifiedCompletionAttestation interface {
	verifiedCompletionAttestation()
}

func (*VerifiedGatewayAttestation) verifiedCompletionAttestation() {}
func (*VerifiedModelAttestation) verifiedCompletionAttestation()   {}

// VerifiedCompletionResult contains a response receipt verified by a Gateway client.
type VerifiedCompletionResult struct {
	ID string
	// Deprecated: use ID. CompletionID contains the same value.
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
	// Attestation contains Gateway evidence for gateway receipts.
	// For provider_tee it is the report used to select the model key;
	// that singular model field is deprecated in favor of Attestations.
	Attestation VerifiedCompletionAttestation
	// Attestations contains every matching verified model deployment for provider_tee
	// receipts. It is empty for Gateway receipts.
	Attestations []VerifiedModelAttestation
}

// ClientOptions configures evidence retrieval.
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
type DirectInferenceOptions struct {
	ClientOptions
	SigningAlgo       SigningAlgo
	E2EE              bool
	OHTTP             bool
	DisableTLSBinding bool
	AttestationTTL    *time.Duration
	ResponseTTL       *time.Duration
	ModelVerification VerificationOptions
	DeploymentPolicy  func(context.Context, string, MeasuredDeployment) error
}
type VerifiedDirectModelAttestations struct {
	ServingAttestation VerifiedDirectModelAttestation
	Attestations       []VerifiedDirectModelAttestation
	SPKIFingerprints   []string
}

// DirectAttestationVerificationResult contains the verified Direct model reports.
type DirectAttestationVerificationResult struct {
	VerifiedDirectModelAttestations
	VerifiedAt time.Time
}

// VerifiedDirectCompletionResult contains the complete preflight-verified signer
// group for a Direct receipt.
type VerifiedDirectCompletionResult struct {
	ID string
	// Deprecated: use ID. CompletionID contains the same value.
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
	Attestations  []VerifiedDirectModelAttestation
}
