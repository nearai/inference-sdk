# Go API reference

Import `nearai "github.com/nearai/inference-sdk/go"`. For walkthroughs, see the
[verification guide](./verification-guide.md); for runnable applications, see
[the examples](../../examples/example-go/README.md).

## Inference client

```go
func NewInferenceClient(o InferenceOptions) (*InferenceClient, error)
func NewDirectInferenceClient(o DirectInferenceOptions) (*DirectInferenceClient, error)

func (c *InferenceClient) Verify(ctx context.Context, model string) (AttestationVerificationResult, error)
func (c *InferenceClient) CreateChatCompletion(ctx context.Context, request any) (json.RawMessage, error)
func (c *InferenceClient) CreateResponse(ctx context.Context, request any) (json.RawMessage, error)
func (c *InferenceClient) CreateMessage(ctx context.Context, request any) (json.RawMessage, error)
func (c *InferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedCompletionResult, error)
func (c *InferenceClient) ClearResponseCache()
func (c *InferenceClient) HTTPClient() *http.Client
func (c *InferenceClient) BaseURL() string
func (c *InferenceClient) RoundTrip(req *http.Request) (*http.Response, error)
func (c *InferenceClient) Close() error

func (c *DirectInferenceClient) Verify(ctx context.Context, model string) (DirectAttestationVerificationResult, error)
func (c *DirectInferenceClient) CreateChatCompletion(ctx context.Context, request any) (json.RawMessage, error)
func (c *DirectInferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedDirectCompletionResult, error)
func (c *DirectInferenceClient) ClearResponseCache()
func (c *DirectInferenceClient) HTTPClient() *http.Client
func (c *DirectInferenceClient) BaseURL() string
func (c *DirectInferenceClient) RoundTrip(req *http.Request) (*http.Response, error)
func (c *DirectInferenceClient) Close() error
```

`CreateChatCompletion`, `CreateResponse`, and `CreateMessage` send JSON requests.
Use `HTTPClient()` for streaming or official SDK integration.
Direct clients support Chat; Responses, Messages, and System One use Gateway clients.

`HTTPClient` uses the inference client as its transport. `BaseURL` supplies the
matching API URL for OpenAI client configuration. Close response bodies and the
inference client when finished.

`CreateMessage(ctx, request)` returns Anthropic JSON as `json.RawMessage`. Use
`HTTPClient()` for streaming Messages. Both require a Gateway client with
field-level E2EE disabled.

See [Messages API](./verification-guide.md#messages-api) and
[Responses API](./verification-guide.md#responses-api) for Gateway receipt
semantics, streaming, and supported privacy options.

### Options and defaults

| Option | Default and behavior |
| --- | --- |
| `ClientOptions.APIKey` | Optional bearer credential. |
| `ClientOptions.BaseURL` | `DefaultBaseURL` (`https://cloud-api.near.ai/v1`) for Gateway; required for direct. |
| `ClientOptions.Headers` | Additional request headers. |
| `ClientOptions.HTTPClient` | Optional HTTP transport. |
| `SigningAlgo` | `Ed25519`; `ECDSA` is also supported. |
| `E2EE` | `false` for Gateway and Direct; set it to `true` to enable encryption. |
| `OHTTP` | `false`; requires Ed25519. Independent of E2EE. |
| `DisableTLSBinding` | `false` for both clients. Set `true` for an application proxy or HTTP endpoint. |
| `AttestationTTL`, `ResponseTTL` | Nil means one hour. Pointer to zero disables reuse/retention; negative durations are invalid. |
| `GatewayVerification`, `ModelVerification` | Default quote/GPU verifiers and attestation policy. Optional deployment callbacks. |
| `DeploymentPolicy` | Optional model-aware admission callback, after `ModelVerification.DeploymentVerifier`. |

Gateway and Direct attestation report requests omit `Authorization`, `api-key`,
and `x-api-key`. Model reports fetched through the Gateway, model metadata,
inference, and response signatures use the configured credentials.

Consume the response body before calling `VerifyResponse`.

## System One decisions

| Method | Result |
| --- | --- |
| `CreateSystemOne(ctx, request)` | `SystemOneResult{Data, DecisionID}` |
| `CreateSystemOneWithHeaders(ctx, request, headers)` | Same result, with per-call headers. |
| `VerifyResponse(ctx, result.DecisionID)` | Verified receipt for the captured request and response. |

Use a Gateway client with E2EE and OHTTP disabled. Each create call verifies the
required deployments and sends one nonstreaming request. `DecisionID` comes from
`X-Generation-Id`. Verify the receipt before using `Data`.

Requests accept `SystemOneRequest` or another JSON-serializable value. Each
question requires `Instructions` as text, an object, or an array. Responses
support `noul`, `choice`, `score`, and `box`; `Extra` preserves unknown fields.
A Box question requires only `Instructions`. Its answer exposes
`Box *SystemOneBoxCoordinates` with finite `Top`, `Bottom`, `Left`, and `Right`
values, plus optional `Confidence *float64`; missing or null confidence becomes `nil`.

Structured content accepts OpenRouter `image_url` JSON parts in state,
instructions, and criteria. An optional JSON `assets` map holds PNG/JPEG images
by reference: `format` (`png`, `jpg`, or `jpeg`), `data_base64` (standard base64),
and optional `type: "image"`. Reference each asset from the request content.
Assets and references pass through unchanged,
including references returned in a Score's `legend`.
`SystemOneRequest.Assets` accepts a map of `SystemOneImageAsset` values.
Structured legend numbers use `json.Number`, while scores, probabilities,
and Box coordinates/confidence use finite `float64` values.

See the [native image example](../../examples/example-go/gateway/systemone/main.go) and
[run instructions](../../examples/README.md#system-one-images).

## Evidence retrieval

Pass each fetched report and its matching `ClientBinding` to the corresponding
verification function.

```go
func NewAttestationClient(o ClientOptions) (*AttestationClient, error)
func NewDirectAttestationClient(o ClientOptions) (*AttestationClient, error)

func (c *AttestationClient) FetchModelMetadata(ctx context.Context, model string) (ModelMetadata, error)
func (c *AttestationClient) FetchGatewayAttestation(ctx context.Context, o FetchOptions) (FetchedGatewayAttestation, error)
func (c *AttestationClient) FetchModelAttestations(ctx context.Context, model string, o FetchOptions) (FetchedModelAttestations, error)
func (c *AttestationClient) FetchCompletionSignature(ctx context.Context, id string, algo SigningAlgo) (CompletionSignature, error)
```

`FetchOptions` selects the signing algorithm, signer filter, and Gateway TLS
binding. `FetchModelMetadata` returns the model ID, provider, and attestation support listed in the model catalog.

## Standalone verification

```go
func VerifyGatewayAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions) (VerifiedAttestation, error)
func VerifyModelAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions) (VerifiedAttestation, error)
func VerifyDirectModelAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions) (VerifiedAttestation, error)
func VerifyDirectModelAttestations(ctx context.Context, fetched FetchedModelAttestations, o VerificationOptions) (VerifiedDirectModelAttestations, error)

func VerifyModelResponse(request, response []byte, signature CompletionSignature, attestation VerifiedAttestation) error
func VerifyGatewayResponse(request, response []byte, signature CompletionSignature, attestation VerifiedAttestation) error
func VerifyDirectModelResponse(id string, request, response []byte, sig CompletionSignature, attestations []VerifiedAttestation) (VerifiedDirectCompletionResult, error)
func FindModelAttestationsForSignature(items []VerifiedAttestation, sig CompletionSignature) ([]VerifiedAttestation, error)
// Deprecated: use FindModelAttestationsForSignature for shared signers.
func FindModelAttestationForSignature(items []VerifiedAttestation, sig CompletionSignature) (VerifiedAttestation, error)

func NewPinnedTransport(base *http.Transport, fingerprints ...string) (*http.Transport, error)
func CreateTDXQuoteVerifier(pccsURL string) QuoteVerifier
func CreateGPUEvidenceVerifier(o GPUVerifierOptions) GPUEvidenceVerifier
```

Pass the verified evidence and exact request/response bytes, before decryption
when E2EE is enabled. Direct response verification returns all matching reports.

`NewPinnedTransport` clones a standard HTTP transport and requires one of the
verified SPKI fingerprints in addition to normal TLS validation. Close its idle
connections when finished.

| Factory | Parameter or field | Default | Description |
| --- | --- | --- | --- |
| `CreateTDXQuoteVerifier` | `pccsURL string` | `https://api.trustedservices.intel.com` | PCCS base URL; DCAP constructs SGX and TDX collateral paths beneath it. An empty string selects the default. |
| `CreateGPUEvidenceVerifier` | `GPUVerifierOptions.NRASURL string` | `https://nras.attestation.nvidia.com/v3/attest/gpu` | Complete GPU evidence POST URL. An empty string selects the default. |
| | `GPUVerifierOptions.JWKSURL string` | `https://nras.attestation.nvidia.com/.well-known/jwks.json` | Independent trusted signing-key URL. An empty string selects the default. |
| | `GPUVerifierOptions.HTTPClient *http.Client` | Built-in HTTP client | Optional HTTP configuration for NRAS and JWKS requests. |

## Encryption helpers

```go
type E2EEModelKey struct {
    SigningAlgo SigningAlgo
    PublicKey   string
}

func PrepareE2EEChatRequest(req *http.Request, key E2EEModelKey) (*PreparedE2EEChatRequest, error)
func (p *PreparedE2EEChatRequest) DecryptJSON(wire []byte) ([]byte, error)
func (p *PreparedE2EEChatRequest) DecryptSSE(source io.ReadCloser) io.ReadCloser

func VerifyOHTTPKeyConfig(a OHTTPAttestation, signer SigningIdentity) ([]byte, error)
func NewOHTTPTransport(config []byte, baseURL string, base http.RoundTripper, forwarded []string) (http.RoundTripper, error)
```

`PreparedE2EEChatRequest.Request` is the encrypted HTTP request. Preparation
consumes the original body. Authenticate `E2EEModelKey` against verified evidence
first. `DecryptSSE` wraps a streaming body; consume it completely and close it.
Use the original encrypted bytes for response signature verification.

Authenticate OHTTP configuration with `VerifyOHTTPKeyConfig` and an already
verified signer before constructing a transport. A nil base transport uses
`http.DefaultTransport`; `forwarded` names additional outer application headers.
See [encryption](#encryption) for field coverage and limits.

## Image provenance API

```go
type ImageProvenancePolicy struct {
    Repository, Workflow, Ref, Commit, SignerIdentity, Issuer string
}

type VerifiedImageProvenance struct {
    Digest, Repository, Workflow, Ref, Commit string
    CertificateIdentity, Issuer, PredicateType string
}

func FetchImageProvenance(ctx context.Context, repository, digest string, o ProvenanceOptions) ([]json.RawMessage, error)
func VerifyImageProvenance(ctx context.Context, bundles []json.RawMessage, digest string, policy ImageProvenancePolicy, o ProvenanceOptions) (VerifiedImageProvenance, error)
func VerifyDeploymentImageProvenance(ctx context.Context, appCompose string, policies map[string]ImageProvenancePolicy, o ProvenanceOptions) error
```

`Repository` is the GitHub `owner/repository`; `Workflow` identifies the build
workflow. `Ref` constrains its source ref and `Commit` optionally pins a source
commit. `SignerIdentity` permits an explicitly trusted reusable workflow identity.
An empty `Issuer` uses `https://token.actions.githubusercontent.com`.

`ProvenanceOptions` contains `TrustedRoot` (Sigstore `root.TrustedMaterial`),
`HTTPClient` (`*http.Client`), and `GitHubToken` (`string`). Nil trusted material
uses the production Sigstore trust root. The deployment helper maps image
repository names to policies and verifies every selected service image.

## Public data types

Public options, evidence, results, and verification callbacks:

```go
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

type ComposeManagerAction map[string]any

type ComposeManagerAttestation struct {
	Actions           []ComposeManagerAction `json:"actions"`
	ActionsHash       string                 `json:"actions_hash"`
	Nonce             string                 `json:"nonce"`
	IntelQuote        string                 `json:"quote"`
	EventLog          json.RawMessage        `json:"event_log"`
	ReportedQuoteData string                 `json:"report_data"`
}

type VerifiedComposeManagerAttestation struct {
	Actions             []ComposeManagerAction
	TCBStatus           string
	AdvisoryIDs         []string
	RuntimeMeasurements RuntimeMeasurements
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
	ID string
	// Deprecated: use ID. CompletionID contains the same value.
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
 // Gateway evidence for gateway receipts.
 // Deprecated for provider_tee receipts: use Attestations for all matching reports.
 // Retains the report used to select the request's model public key;
 Attestation *VerifiedAttestation
 // Every matching verified model deployment for provider_tee receipts.
	Attestations []VerifiedAttestation
}

// ClientOptions configures evidence retrieval.
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
	ServingAttestation VerifiedAttestation
	Attestations       []VerifiedAttestation
	SPKIFingerprints   []string
}

type DirectAttestationVerificationResult struct {
	VerifiedDirectModelAttestations
	VerifiedAt time.Time
}

type VerifiedDirectCompletionResult struct {
	ID string
	// Deprecated: use ID. CompletionID contains the same value.
	CompletionID  string
	SignatureKind string
	Signature     CompletionSignature
	Attestations  []VerifiedAttestation
}
```

## Clients and lifecycle

`NewInferenceClient(InferenceOptions)` creates a Gateway client.
`NewDirectInferenceClient(DirectInferenceOptions)` requires an explicit base URL.
Direct clients verify all returned model attestations and pin requests to the
selected signer group's TLS fingerprints. E2EE defaults to `false` for both clients.

Close the client and HTTP response bodies when finished.

`Verify(ctx, model)` verifies deployments before inference. Gateway clients
return `AttestationVerificationResult`; Direct clients return
`DirectAttestationVerificationResult`. Both include all verified model reports.

`AttestationTTL` and `ResponseTTL` default to one hour. A pointer to zero disables
the corresponding cache. Verify responses before `ResponseTTL` expires;
`ClearResponseCache()` discards retained responses.

## Attestation verification

All returned model reports must pass verification. Configure `AcceptedTCBStatuses`
to select accepted TCB states and `RequireGPUEvidence` to require GPU evidence.

Use `QuoteVerifier`, `GPUVerifier`, and `DeploymentVerifier` for custom verification.

Gateway requests use attested TLS pinning by default. Set `DisableTLSBinding`
for an application proxy whose TLS certificate belongs to the proxy.

Models without NEAR model attestation use Gateway-only (Incognito) verification.
E2EE and model deployment policies require model attestation.

## Response verification

`VerifyResponse(ctx, completionID)` verifies retained, exact request/response
bytes against evidence saved before transmission, including ciphertext under
E2EE. It distinguishes:

- `provider_tee`: a verified model signer signed the exact bytes and canonical
  model ID.
- `gateway`: a verified Gateway signer signed the exact client-visible bytes.

`VerifiedCompletionResult.Attestations` contains all reports sharing the selected
model signer. For Gateway receipts, `Attestation` contains Gateway evidence.
The singular `Attestation` is deprecated for model receipts: it holds the report
selected for the request key; use `Attestations` for model evidence.
`VerifiedDirectCompletionResult` contains the matching reports in `Attestations`.

Manual workflow APIs:

- `NewAttestationClient` / `NewDirectAttestationClient` retrieve metadata,
  Gateway/model reports, and completion signatures. Only attestation-report
  fetches generate fresh random nonces.
- `VerifyGatewayAttestation`, `VerifyModelAttestation`,
  `VerifyDirectModelAttestation`, and `VerifyDirectModelAttestations` authenticate
  those reports. The plural direct helper checks serving-report membership and
  binds its optional fingerprint to the supplied observed peer.
- `VerifyGatewayResponse`, `VerifyModelResponse`, `VerifyDirectModelResponse`
  verify exact bytes using already authenticated evidence.
- `FindModelAttestationsForSignature` selects all matching reports from already
  verified inputs. Use `VerifyModelResponse` to verify the signature.
- The deprecated `FindModelAttestationForSignature` returns the first matching
  report in input order. An absent signer returns an error.

## Encryption

E2EE encrypts supported Chat fields to the verified model key.

Protected fields include message content, reasoning, audio, tool definitions and
calls, logprobs, and streaming tool-result output. Use `PrepareE2EEChatRequest`
with a verified model key for standalone encryption.

OHTTP encrypts encapsulated requests and responses to the Gateway or Direct
endpoint. It is independent of E2EE and also supports Gateway-only models.
Authenticate the key configuration before using `NewOHTTPTransport`.

## Deployment and image policies

`DeploymentPolicy(ctx, model, deployment)` applies application-specific model
deployment checks. Use image policies to require particular GitHub builds.

`VerifyDeploymentImageProvenance` checks required images against their GitHub
build policies. Pass `AppCompose` from the deployment callback or from an
already verified deployment.
Each configured image repository is required, with a literal SHA-256 digest.

`FetchImageProvenance` retrieves Sigstore bundles. `VerifyImageProvenance` checks
them against the artifact digest and GitHub build policy. Use `Commit` to pin
a source version and `SignerIdentity` for a reusable signing workflow.

### Compose Manager deployment provenance

Authenticated Compose Manager evidence is available as `MeasuredDeployment.ComposeManager`.

`VerifyComposeManagerDeploymentImageProvenance(ctx, deployment, imagePolicies, options)`
verifies the recorded Compose file and selected container images, including the
Compose Manager startup image, against the supplied policies. Use in a model
deployment callback.

| Option | Meaning |
| --- | --- |
| `ComposeRepository` | Trusted `owner/repo`; defaults to `nearai/cvm-compose-files`. |
| `ComposeFile` | Exact file path, or the latest `compose_up` across all files. |
| `ComposeManagerImagePolicy` | Required `ImageRepository` and `Build` (`ImageProvenancePolicy`) for the latest `compose_manager_started` image. |
| `ProvenanceOptions` | Shared proof options: `TrustedRoot`, `HTTPClient`, `GitHubToken`, `GitHubAPIURL`. |

See the [model image guide](./verification-guide.md#images-deployed-by-compose-manager)
for a complete example.

`GitHubAPIURL` sets the GitHub API base URL for compose files and image proofs;
it defaults to `https://api.github.com`. When using a GitHub token in a frontend
is impractical, set it to a GitHub-compatible endpoint on your backend. The
backend supplies the GitHub credentials; the SDK omits `GitHubToken` when
`GitHubAPIURL` is set. Redirects and pagination outside the requested artifact
are rejected.

## Errors and development

```go
type Error struct {
    Code      string
    Details   map[string]any
    Retryable bool
    Cause     error
}

func (e *Error) Error() string
func (e *Error) Unwrap() error
```

Use `errors.As(err, &sdkError)` for `*nearai.Error`, and handle failures by `Code`.
`Retryable` indicates whether retrying the failed operation may succeed.

For development commands, see [Testing](../../TESTING.md#validation).
