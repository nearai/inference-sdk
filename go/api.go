package nearai

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// AttestationClient fetches evidence without making any claim that it is verified.
type AttestationClient struct {
	base    *url.URL
	headers http.Header
	http    *http.Client
	direct  bool
}

func NewAttestationClient(o ClientOptions) (*AttestationClient, error) { return newAPIClient(o, false) }
func NewDirectAttestationClient(o ClientOptions) (*AttestationClient, error) {
	return newAPIClient(o, true)
}
func newAPIClient(o ClientOptions, direct bool) (*AttestationClient, error) {
	if o.BaseURL == "" {
		if direct {
			return nil, failure("api.invalid_input", nil)
		}
		o.BaseURL = DefaultBaseURL
	}
	u, e := url.Parse(o.BaseURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, failure("api.invalid_input", e)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	h := make(http.Header)
	for k, v := range o.Headers {
		h[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	if o.APIKey != "" {
		h.Set("Authorization", "Bearer "+o.APIKey)
		h.Del("Api-Key")
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	if o.HTTPClient != nil {
		*client = *o.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &AttestationClient{base: u, headers: h, http: client, direct: direct}, nil
}
func (c *AttestationClient) endpoint(path string, q url.Values) string {
	u := *c.base
	unescaped, _ := url.PathUnescape(path)
	u.Path += unescaped
	u.RawPath = c.base.EscapedPath() + path
	u.RawQuery = q.Encode()
	return u.String()
}
func nonce() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e == nil && int64(len(b)) > limit {
		return nil, failure("api.body_too_large", nil)
	}
	return b, e
}
func (c *AttestationClient) get(ctx context.Context, path string, q url.Values) ([]byte, string, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", c.endpoint(path, q), nil)
	if e != nil {
		return nil, "", e
	}
	req.Header = c.headers.Clone()
	req.Header.Set(NoAliasingHeader, "true")
	res, e := c.http.Do(req)
	if e != nil {
		var sdk *Error
		if errors.As(e, &sdk) {
			return nil, "", sdk
		}
		return nil, "", &Error{Code: "api.transport_failed", Retryable: true, Cause: e}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, "", &Error{Code: "api.http_status", Details: map[string]any{"status": res.StatusCode}, Retryable: res.StatusCode == 408 || res.StatusCode == 425 || res.StatusCode == 429 || res.StatusCode >= 500}
	}
	b, e := readBounded(res.Body, 16<<20)
	if e != nil {
		return nil, "", e
	}
	if !json.Valid(b) {
		return nil, "", failure("api.invalid_json", nil)
	}
	fp := ""
	if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(res.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
		fp = hex.EncodeToString(sum[:])
	}
	return b, fp, nil
}
func optionsQuery(o FetchOptions) (url.Values, error) {
	q := url.Values{}
	if o.SigningAlgo != "" {
		if o.SigningAlgo != Ed25519 && o.SigningAlgo != ECDSA {
			return nil, failure("api.invalid_input", nil)
		}
		q.Set("signing_algo", string(o.SigningAlgo))
	}
	if o.SigningAddress != "" {
		if _, e := signingBytes(SigningIdentity{o.SigningAlgo, o.SigningAddress}); e != nil {
			return nil, e
		}
		q.Set("signing_address", o.SigningAddress)
	}
	return q, nil
}
func (c *AttestationClient) FetchModelMetadata(ctx context.Context, model string) (ModelMetadata, error) {
	var m ModelMetadata
	if model == "" {
		return m, failure("api.invalid_input", nil)
	}
	if model == "." || model == ".." {
		return m, failure("api.invalid_input", nil)
	}
	b, _, e := c.get(ctx, "model/"+url.PathEscape(model), nil)
	if e != nil {
		return m, e
	}
	var raw struct {
		Metadata struct {
			Provider  *string `json:"providerType"`
			Supported *bool   `json:"attestationSupported"`
		} `json:"metadata"`
	}
	if e = json.Unmarshal(b, &raw); e != nil || raw.Metadata.Provider == nil || raw.Metadata.Supported == nil {
		return m, failure("api.invalid_response", e)
	}
	m.ModelID = model
	m.ProviderType = *raw.Metadata.Provider
	m.AttestationSupported = *raw.Metadata.Supported
	return m, nil
}
func (c *AttestationClient) FetchGatewayAttestation(ctx context.Context, o FetchOptions) (FetchedGatewayAttestation, error) {
	var out FetchedGatewayAttestation
	q, e := optionsQuery(o)
	if e != nil {
		return out, e
	}
	n := nonce()
	q.Set("nonce", n)
	q.Set("include_tls_fingerprint", fmt.Sprint(!o.DisableTLSBinding))
	b, fp, e := c.get(ctx, "attestation/report", q)
	if e != nil {
		return out, e
	}
	var raw struct {
		Gateway json.RawMessage   `json:"gateway_attestation"`
		OHTTP   *OHTTPAttestation `json:"ohttp_attestation"`
	}
	if e = json.Unmarshal(b, &raw); e != nil {
		return out, failure("api.invalid_response", e)
	}
	a, e := decodeAttestation(raw.Gateway)
	if e != nil {
		return out, e
	}
	if a.ReportedQuoteData == "" || !sameHex(a.Nonce, n) || (a.SPKIFingerprint != "") == o.DisableTLSBinding {
		return out, failure("api.invalid_response", nil)
	}
	if !o.DisableTLSBinding && fp == "" {
		return out, failure("binding.spki_fingerprint_required", nil)
	}
	return FetchedGatewayAttestation{a, ClientBinding{n, fp}, raw.OHTTP}, nil
}
func (c *AttestationClient) FetchModelAttestations(ctx context.Context, model string, o FetchOptions) (FetchedModelAttestations, error) {
	var out FetchedModelAttestations
	q, e := optionsQuery(o)
	if e != nil {
		return out, e
	}
	n := nonce()
	q.Set("nonce", n)
	q.Set("include_tls_fingerprint", "false")
	if !c.direct {
		if model == "" {
			return out, failure("api.invalid_input", nil)
		}
		q.Set("model", model)
		q.Set("provider", "near")
	}
	b, _, e := c.get(ctx, "attestation/report", q)
	if e != nil {
		return out, e
	}
	var raw map[string]json.RawMessage
	if e = json.Unmarshal(b, &raw); e != nil || raw == nil {
		return out, failure("api.invalid_response", e)
	}
	field := "model_attestations"
	if c.direct {
		field = "all_attestations"
	}
	var entries []json.RawMessage
	if data, ok := raw[field]; ok {
		if e = json.Unmarshal(data, &entries); e != nil || entries == nil {
			return out, failure("api.invalid_response", e)
		}
	}
	for _, entry := range entries {
		a, e := decodeAttestation(entry)
		if e != nil {
			return out, e
		}
		if !sameHex(a.Nonce, n) || a.SPKIFingerprint != "" || (c.direct && a.ModelName == "") {
			return out, failure("api.invalid_response", nil)
		}
		out.Attestations = append(out.Attestations, a)
	}
	if c.direct {
		a, e := decodeAttestation(b)
		if e != nil {
			return out, e
		}
		found := false
		for i := range out.Attestations {
			if reflect.DeepEqual(a, out.Attestations[i]) {
				out.ServingAttestation = &out.Attestations[i]
				found = true
				break
			}
		}
		if !found {
			return out, failure("api.invalid_response", nil)
		}
	}
	if data := raw["ohttp_attestation"]; len(data) > 0 {
		if e = json.Unmarshal(data, &out.OHTTPAttestation); e != nil {
			return out, failure("api.invalid_response", e)
		}
	}
	out.ClientBinding = ClientBinding{Nonce: n}
	return out, nil
}
func (c *AttestationClient) FetchCompletionSignature(ctx context.Context, id string, algo SigningAlgo) (CompletionSignature, error) {
	var sig CompletionSignature
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return sig, failure("api.invalid_input", nil)
	}
	q, e := optionsQuery(FetchOptions{SigningAlgo: algo})
	if e != nil {
		return sig, e
	}
	b, _, e := c.get(ctx, "signature/"+url.PathEscape(id), q)
	if e != nil {
		var sdk *Error
		if errors.As(e, &sdk) && sdk.Code == "api.http_status" && sdk.Details["status"] == http.StatusNotFound {
			sdk.Retryable = true
		}
		return sig, e
	}
	var raw struct {
		Kind      string      `json:"signature_kind"`
		Text      *string     `json:"text"`
		Signature *string     `json:"signature"`
		Algo      SigningAlgo `json:"signing_algo"`
		Address   string      `json:"signing_address"`
		ErrorCode string      `json:"error_code"`
		Message   string      `json:"message"`
	}
	if e = json.Unmarshal(b, &raw); e != nil {
		return sig, failure("api.invalid_response", e)
	}
	if raw.ErrorCode != "" {
		if raw.Text != nil || raw.Signature != nil || raw.Algo != "" || raw.Address != "" || raw.Kind != "" {
			return sig, failure("api.invalid_response", nil)
		}
		return sig, &Error{Code: "api.completion_signature_unavailable", Details: map[string]any{"providerErrorCode": raw.ErrorCode, "providerMessage": raw.Message}}
	}
	if c.direct {
		if raw.Kind != "" && raw.Kind != "provider_tee" {
			return sig, failure("api.invalid_response", nil)
		}
		raw.Kind = "provider_tee"
	}
	if raw.Text == nil || raw.Signature == nil || (raw.Kind != "gateway" && raw.Kind != "provider_tee") {
		return sig, failure("api.invalid_response", nil)
	}
	sig = CompletionSignature{raw.Kind, *raw.Text, *raw.Signature, SigningIdentity{raw.Algo, raw.Address}}
	if _, e = signingBytes(sig.Signer); e != nil {
		return sig, failure("api.invalid_response", e)
	}
	return sig, nil
}
func decodeAttestation(data []byte) (Attestation, error) {
	var a Attestation
	var raw struct {
		Nonce    string          `json:"request_nonce"`
		Algo     SigningAlgo     `json:"signing_algo"`
		Address  string          `json:"signing_address"`
		Quote    string          `json:"intel_quote"`
		EventLog json.RawMessage `json:"event_log"`
		Info     struct {
			TCB        json.RawMessage `json:"tcb_info"`
			InstanceID string          `json:"instance_id"`
		} `json:"info"`
		Report    string  `json:"report_data"`
		PublicKey string  `json:"signing_public_key"`
		GPU       *string `json:"nvidia_payload"`
		FP        string  `json:"tls_cert_fingerprint"`
		Model     string  `json:"model_name"`
	}
	if e := json.Unmarshal(data, &raw); e != nil {
		return a, failure("api.invalid_response", e)
	}
	var encoded string
	if json.Unmarshal(raw.Info.TCB, &encoded) == nil {
		raw.Info.TCB = []byte(encoded)
	}
	var tcb struct {
		Compose *string `json:"app_compose"`
	}
	if e := json.Unmarshal(raw.Info.TCB, &tcb); e != nil || tcb.Compose == nil || raw.Quote == "" || len(raw.EventLog) == 0 {
		return a, failure("api.invalid_response", e)
	}
	a = Attestation{Nonce: raw.Nonce, Signer: SigningIdentity{raw.Algo, raw.Address}, IntelQuote: raw.Quote, EventLog: raw.EventLog, AppCompose: *tcb.Compose, ReportedQuoteData: raw.Report, SigningPublicKey: raw.PublicKey, NvidiaPayload: raw.GPU, SPKIFingerprint: raw.FP, ModelName: raw.Model, InstanceID: raw.Info.InstanceID}
	if _, e := hexSize(a.Nonce, 32); e != nil {
		return a, failure("api.invalid_response", e)
	}
	if _, e := signingBytes(a.Signer); e != nil {
		return a, failure("api.invalid_response", e)
	}
	return a, nil
}

// NewPinnedTransport clones a standard HTTP transport and enforces the quote-
// authenticated SPKI pin during TLS handshake, before request bytes are sent.
func NewPinnedTransport(base *http.Transport, fingerprint string) (*http.Transport, error) {
	expected, e := hexSize(fingerprint, 32)
	if e != nil {
		return nil, e
	}
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	if base.DialTLSContext != nil || base.DialTLS != nil {
		return nil, failure("api.invalid_input", nil)
	}
	t := base.Clone()
	if t.IdleConnTimeout == 0 {
		t.IdleConnTimeout = 90 * time.Second
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		t.TLSClientConfig = t.TLSClientConfig.Clone()
	}
	if t.TLSClientConfig.InsecureSkipVerify {
		return nil, failure("api.invalid_input", nil)
	}
	previous := t.TLSClientConfig.VerifyConnection
	t.TLSClientConfig.VerifyConnection = func(s tls.ConnectionState) error {
		if previous != nil {
			if e := previous(s); e != nil {
				return e
			}
		}
		if len(s.PeerCertificates) == 0 {
			return failure("binding.spki_fingerprint_required", nil)
		}
		sum := sha256.Sum256(s.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if hex.EncodeToString(sum[:]) != hex.EncodeToString(expected) {
			return failure("binding.spki_fingerprint_mismatch", nil)
		}
		return nil
	}
	return t, nil
}

// FindModelAttestationForSignature rejects ambiguous signers, even when multiple
// deployments share a key. Inference sessions retain the selected routing key.
func FindModelAttestationForSignature(items []VerifiedAttestation, sig CompletionSignature) (VerifiedAttestation, error) {
	var found VerifiedAttestation
	count := 0
	if sig.Kind != "provider_tee" {
		return found, failure("api.invalid_input", nil)
	}
	for _, a := range items {
		if a.Signer.SigningAlgo == sig.Signer.SigningAlgo && sameHex(a.Signer.SigningAddress, sig.Signer.SigningAddress) {
			found = a
			count++
		}
	}
	if count != 1 {
		return VerifiedAttestation{}, detail("api.model_attestation_not_found", "matches", count)
	}
	return found, nil
}
