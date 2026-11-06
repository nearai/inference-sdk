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

`CreateChatCompletion`, `CreateResponse`, and `CreateMessage` send non-streaming JSON requests.
Use `HTTPClient` for streaming or the official OpenAI Go SDK. `RoundTrip` accepts
POST requests at the configured Chat Completions, Gateway Responses, and Messages creation
endpoints. It verifies deployments before transmission and retains the exact wire
bytes after complete body consumption. It does not automatically verify receipts.
`DirectInferenceClient` supports Chat Completions and its verification/transport
lifecycle; Responses, Messages, and System One use `InferenceClient`.

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
| `ClientOptions.APIKey` | Optional application credential; the empty string omits it. The library does not read environment variables. |
| `ClientOptions.BaseURL` | `DefaultBaseURL` (`https://cloud-api.near.ai/v1`) for Gateway; required for direct. |
| `ClientOptions.Headers` | Additional request headers. |
| `ClientOptions.HTTPClient` | Optional borrowed HTTP client; custom transports are trusted application code. |
| `SigningAlgo` | `Ed25519`; `ECDSA` is also supported. |
| `E2EE` | `false` for Gateway and Direct; set it to `true` to enable encryption. |
| `OHTTP` | `false`; requires Ed25519. Independent of E2EE. |
| `DisableTLSBinding` | `false` for both clients. Set `true` to disable attested TLS binding. |
| `AttestationTTL`, `ResponseTTL` | Nil means one hour. Pointer to zero disables reuse/retention; negative durations are invalid. |
| `GatewayVerification`, `ModelVerification` | Default quote/GPU verifiers and attestation policy. Optional deployment callbacks. |
| `DeploymentPolicy` | Optional model-aware admission callback, after `ModelVerification.DeploymentVerifier`. |

Use `NewAttestationClient(ClientOptions{})` to fetch attestation without credentials.
Gateway and direct attestation requests omit `Authorization`, `api-key`, and
`x-api-key`, including values supplied in `Headers`. Other custom headers are
preserved. Metadata, inference, and signature requests use configured authentication.

Model reports through the Gateway use the client's configured API key or authentication
headers. Listed models can be queried without credentials; unlisted models require a
key for an organization granted access. With standalone evidence clients, verify the
Gateway before fetching an authenticated model report. Integrated clients perform
this ordering automatically.

See [lifecycle](#clients-and-lifecycle) for cancellation and retention behavior.

Chat and Responses stop interpreting SSE events at `[DONE]` and also accept
normal EOF. Consume the response body before `VerifyResponse`. Messages require
a valid `message_stop` event.

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

System One shares Chat's per-model session and the client's
receipt retention and verification.
Cancellation uses `ctx`, and `Close` cancels outstanding operations.

Inference is sent once. Retry transient receipt lookups through the verification
method while the response remains cached.

## Evidence retrieval

Fetching reports does not verify them. Keep the returned `ClientBinding` with
its reports and pass both to the verification functions.

```go
func NewAttestationClient(o ClientOptions) (*AttestationClient, error)
func NewDirectAttestationClient(o ClientOptions) (*AttestationClient, error)

func (c *AttestationClient) FetchModelMetadata(ctx context.Context, model string) (ModelMetadata, error)
func (c *AttestationClient) FetchGatewayAttestation(ctx context.Context, o FetchOptions) (FetchedGatewayAttestation, error)
func (c *AttestationClient) FetchModelAttestations(ctx context.Context, model string, o FetchOptions) (FetchedModelAttestations, error)
func (c *AttestationClient) FetchCompletionSignature(ctx context.Context, id string, algo SigningAlgo) (CompletionSignature, error)
```

`FetchOptions` selects the signing algorithm, optionally a signing address, and
whether to disable TLS binding. `FetchGatewayAttestation` and
`FetchModelAttestations` generate fresh nonces; metadata and completion-signature
retrieval do not. Model metadata
reports the canonical model ID, provider type, and whether model attestation is
supported. Direct clients retrieve model evidence without a Gateway.

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

Response verification takes exact transmitted bytes, including ciphertext when
E2EE is enabled. Do not reserialize parsed JSON. Authenticate the attestation
before passing it to a response helper. The direct plural helpers preserve all
matching instances; a shared signer does not uniquely identify an instance.

`NewPinnedTransport` clones a standard HTTP transport and checks the attested
SPKI fingerprint in addition to normal TLS validation. Close its idle connections
when finished.

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
These helpers decrypt content but do not verify response signatures.

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

These structures describe options, fetched evidence, verified results, and
verification callbacks. A fetched `Attestation` is untrusted until verified.
`VerifiedAttestation.Deployment` contains measured app-compose text and runtime
hashes; applications decide whether those measurements are acceptable.

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
 // it does not identify the serving instance.
 Attestation *VerifiedAttestation
 // Every matching verified model deployment for provider_tee receipts.
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
// Direct clients verify attested TLS identities by default.
type DirectInferenceOptions struct {
	DisableTLSBinding bool
	ClientOptions
	SigningAlgo       SigningAlgo
	E2EE              bool
	OHTTP             bool
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
`NewDirectInferenceClient(DirectInferenceOptions)` creates a `DirectInferenceClient`
and requires an explicit base URL. Its options configure Direct inference without
Gateway verification settings.
Both clients leave E2EE disabled unless their `E2EE` option is set to `true`.
Direct clients are experimental and verify the serving TLS peer and every returned
report. Subsequent requests are pinned to the verified fingerprints sharing the
selected model signer.

Always close the client and each HTTP response body. `Close` cancels shared
verification work and active requests, clears retained data, and closes owned
idle connections. Caller-supplied HTTP clients/transports are borrowed.

`Verify(ctx, model)` performs deployment admission without sending Chat.
Gateway clients return `AttestationVerificationResult` with Gateway evidence,
all model reports, and `VerifiedAt`. Direct clients return
`DirectAttestationVerificationResult` with all reports in `Attestations`, the
preflight endpoint's `ServingAttestation`, and `VerifiedAt`. `SPKIFingerprints` contains the verified TLS identities. The serving report identifies the
preflight endpoint, not the instance serving a later completion. Cache hits
preserve the original timestamp.

`AttestationTTL` and `ResponseTTL` are optional `*time.Duration` values, defaulting
to one hour. A pointer to zero disables reuse/retention. Expired records are
unavailable immediately and cleaned up periodically. Simultaneous callers share
preflight and response-verification work. Cancelling one waiter leaves other
waiters intact; shared verification is limited to two minutes. Failed preflight
is not cached. Retryable signature retrieval failures can be attempted again
without replaying the completion.

Streaming is incremental, but signature verification requires retaining the wire body.
Once verification caches a success or a failure that cannot be retried, it releases
the captured request and response bytes. Subsequent calls reuse that outcome until
the original TTL expires. Unverified records and retryable failures retain their
bytes until expiry or explicit cleanup. A duplicate
retained ID fails with `api.duplicate_completion_id` and preserves the original
receipt. An expired ID can be reused.

Call `ClearResponseCache()` when discarding a conversation. It clears captured
request/response bytes and cached receipt results while keeping the client and
attestation sessions reusable. Cleared IDs become unavailable to `VerifyResponse`.
Ongoing response captures stay discarded when they finish.
To end active work and release its buffers, also cancel the requests and finish
any ongoing verification. Direct clients support the same cleanup method.

## Verification guarantees

All returned model reports must verify, including instances sharing a signer.
By default, `UpToDate`, `OutOfDate`, and `TDRelaunchAdvised` TCB states are accepted. An explicitly
empty `AcceptedTCBStatuses` rejects all states. Debug-enabled quotes are rejected.
Quote report data binds the client nonce and signer, plus the Gateway's SPKI
fingerprint when requested. The SDK replays RTMR3 events and checks the hash of
the exact app-compose text against MRCONFIGID.

GPU evidence, when supplied, must carry the same nonce and an NVIDIA-signed
ES384 overall verdict with the expected issuer and valid timestamps. Set
`RequireGPUEvidence` to reject missing evidence. `QuoteVerifier`, `GPUVerifier`,
and `DeploymentVerifier` hooks are trusted application code: custom verifiers
must authenticate their inputs, not merely parse them.

Gateway pinning checks the observed peer during the TLS handshake before sending
Chat, model-evidence, or signature requests. It supports the default transport
or a caller's `*http.Transport` with normal TLS verification and no custom
`DialTLS`/`DialTLSContext`. `DisableTLSBinding: true` is an explicit opt-out for
application proxies; it no longer establishes the attested Gateway's TLS identity.
Requests do not follow redirects. The configured credentials take precedence over
credentials supplied by an external OpenAI client.

Model metadata uses the canonical request model ID with aliasing disabled. Models
without supported NEAR model attestation use Gateway-only verification. E2EE and
model deployment policies reject that flow before transmitting Chat.

## Response verification

`VerifyResponse(ctx, completionID)` verifies retained, exact request/response
bytes against evidence saved before transmission, including ciphertext under
E2EE. It distinguishes:

- `provider_tee`: a verified model signer signed the exact bytes and canonical
  model ID. This does not authenticate the Gateway's handling of them.
- `gateway`: a verified Gateway signer signed the exact client-visible bytes.
  This does not prove execution in a model TEE.

`VerifiedCompletionResult.Attestations` includes every verified model report
matching a `provider_tee` response's signer. Gateway clients also require that
signer to match the key selected for the request. Reading `Attestation` for
`provider_tee` receipts is deprecated: use `Attestations` for model evidence. The
old field retains the report used to select the request's model public key and
does not identify the serving instance.
For `gateway` receipts, `Attestation` contains Gateway evidence and `Attestations`
is empty. Direct clients return `VerifiedDirectCompletionResult`, which contains
the matching group in `Attestations` and no singular `Attestation` field. A shared
signing key cannot identify an individual serving instance.
`VerifyDirectModelResponse` returns the same Direct result type for manual workflows.

Signatures and independently verified deployments do not establish a complete
cryptographic chain from model execution through Gateway rewriting.

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
  verified inputs and rejects missing matches. It does not verify attestations
  or response signatures. Call `VerifyModelResponse` separately; if a model key
  was selected before sending, pass the report used to select that key.
- The deprecated `FindModelAttestationForSignature` retains its exactly-one-match
  contract and rejects missing or ambiguous matches.

## Encryption

E2EE uses Ed25519-to-X25519 / HKDF-SHA256 / XChaCha20-Poly1305 or the legacy
secp256k1 / HKDF-SHA256 / AES-GCM protocol. Each request gets a fresh response key.
The model key is bound to its quote-authenticated signer before use.

Protected request fields include message content (including serialized multimodal
content), reasoning, name, refusal, audio data, tool/function names and arguments,
tool descriptions/parameters, and selected function names. Protected response
fields include message/delta content, reasoning, refusal, audio data, tool/function
names and arguments, logprobs, and streaming tool-result output. Other fields,
including model IDs, roles and tool-call IDs, remain visible. The standalone
`PrepareE2EEChatRequest` consumes the supplied body and returns a new request plus
`DecryptJSON`/`DecryptSSE` helpers; it does not attest the supplied model key or
verify response signatures.

OHTTP protects the whole Chat HTTP exchange to the Gateway (or experimental
direct endpoint). Authorization and explicitly forwarded application headers are
visible to that endpoint; content and E2EE headers are inside the encrypted
exchange. It is independent of field E2EE and works with Gateway-only models.
`NewOHTTPTransport` requires an already authenticated key configuration.
OHTTP/BHTTP responses authenticate the final encrypted frame, including trailing
padding after SSE `[DONE]`; missing, truncated or corrupt frames fail. All decrypted
bytes, including headers and padding, count toward 1 GiB. Header sections are
bounded to 1 MiB and at most 32 informational responses precede the final response.

## Deployment and image policies

`DeploymentPolicy(ctx, model, deployment)` runs after the model's configured
`DeploymentVerifier`. Verification alone does not approve a publisher, image,
measurement or release version. Supply policies for those decisions.
Deployment callbacks inspect the verified evidence as read-only input.

`VerifyDeploymentImageProvenance` selects digest-pinned images from measured
app-compose JSON's `docker_compose_file`. Every configured image repository must
occur, and every matching service must pin a digest. Unresolved image variables
and malformed Compose are rejected before fetching evidence.

`FetchImageProvenance` retrieves inline GitHub bundles, including pagination.
Provenance fetch limits:

| Resource | Limit |
| --- | --- |
| Response page | 16 MiB and 100 attestations |
| Entire fetch | 32 pages and 64 MiB |
| Combined `Link` headers per page | 8 KiB |
| Encoded `before`/`after` query | 4 KiB |

Body limits apply while reading, including responses without `Content-Length`,
and fail with `api.body_too_large`. Other limits fail with `api.invalid_response`.
Limit failures are non-retryable and return no partial bundles.

Pagination contributes only a cursor; supplied origins/paths and bundle URLs are
never followed. `ProvenanceOptions.GitHubToken` is separate from the Gateway key.
`VerifyImageProvenance` checks Sigstore signatures, certificate transparency,
transparency logs, the artifact digest, GitHub build identity, source ref/commit,
and SLSA provenance. `SignerIdentity` supports explicitly trusted reusable
workflows. `Commit` optionally pins reviewed source. The default Sigstore root
uses authenticated production TUF updates; `TrustedRoot` supports offline trusted
material. Trust-root refresh uses the upstream synchronous API; cancellation is
checked before and after it, not during its network operation.

### Compose Manager deployment provenance

`Attestation.ComposeManagerAttestation` holds optional raw manager evidence.
When present in a model report, verification checks its quote/TCB, nonce, canonical
action hash, event log, and binding to the model's measured app-compose. The
callback receives `MeasuredDeployment.ComposeManager`, including authenticated
actions, TCB status, advisory IDs and runtime measurements.

`VerifyComposeManagerDeploymentImageProvenance(ctx, deployment, imagePolicies, options)`
requires manager evidence, selects the latest matching `compose_up`, fetches its
recorded file at its commit, verifies exact SHA-256 and UTF-8, and verifies images
in the action's named `services`. An absent/empty service list selects the entire
file; unknown services fail. Unselected images cannot satisfy a required policy.

| Option | Meaning |
| --- | --- |
| `ComposeRepository` | Trusted `owner/repo`; defaults to `nearai/cvm-compose-files`. |
| `ComposeFile` | Exact file path, or the latest `compose_up` across all files. |
| `ComposeManagerImagePolicy` | Required `ImageRepository` and `Build` (`ImageProvenancePolicy`) for the latest `compose_manager_started` image. |
| `ProvenanceOptions` | Shared proof options: `TrustedRoot`, `HTTPClient`, `GitHubToken`, `GitHubAPIURL`. |

Compose files are limited to 8 MiB before hashing or parsing. Missing evidence,
hash mismatches, and rejected image policies fail verification. See the
[guide](./verification-guide.md#images-deployed-by-compose-manager) for usage
and evidence scope.

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

Use `errors.As(err, &sdkError)` for `*nearai.Error`. Branch on `Code`, inspect
`Details`, and use `errors.Is` for wrapped context cancellation. `Retryable`
indicates a failed external operation may succeed on another attempt; it never
authorizes automatic replay of inference. The SDK does not retry completions.

From `go/` (no native library setup required):

```sh
gofmt -w *.go internal/dcap/*.go
go vet ./...
go test -race -cover ./...
```

The test suite includes cross-language E2EE vectors, signed provenance fixtures,
embedded DCAP verification, admission and exact signatures, shared cancellation,
stream failures, TLS rejection, and chunked OHTTP authentication. It does not
make paid inference calls.
