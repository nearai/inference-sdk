package nearai

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

// AttestationClient fetches evidence without making any claim that it is verified.
type AttestationClient struct{ *apiClient }

// DirectAttestationClient fetches reports and signatures from one Direct endpoint.
type DirectAttestationClient struct{ *apiClient }

type apiClient struct {
	base    *url.URL
	headers http.Header
	http    *http.Client
	direct  bool
}

func NewAttestationClient(o ClientOptions) (*AttestationClient, error) {
	api, err := newAPIClient(o, false)
	if err != nil {
		return nil, err
	}
	return &AttestationClient{api}, nil
}

func NewDirectAttestationClient(o ClientOptions) (*DirectAttestationClient, error) {
	api, err := newAPIClient(o, true)
	if err != nil {
		return nil, err
	}
	return &DirectAttestationClient{api}, nil
}

func newAPIClient(o ClientOptions, direct bool) (*apiClient, error) {
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
	return &apiClient{base: u, headers: h, http: client, direct: direct}, nil
}

func (c *apiClient) endpoint(path string, q url.Values) string {
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
	readLimit := limit
	if limit < math.MaxInt64 {
		readLimit++
	}
	b, e := io.ReadAll(io.LimitReader(r, readLimit))
	if e == nil && int64(len(b)) > limit {
		return nil, failure("api.body_too_large", nil)
	}
	return b, e
}

// Decode before capturing signed bytes or applying response size limits.
func decodeResponse(res *http.Response) error {
	var reader io.Reader
	switch strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding"))) {
	case "gzip":
		var err error
		reader, err = gzip.NewReader(res.Body)
		if err != nil {
			return err
		}
	case "br":
		reader = brotli.NewReader(res.Body)
	default:
		return nil
	}
	res.Body = struct {
		io.Reader
		io.Closer
	}{reader, res.Body}
	res.Header.Del("Content-Encoding")
	res.Header.Del("Content-Length")
	res.ContentLength = -1
	res.Uncompressed = true
	return nil
}

func readResponseBounded(res *http.Response, limit int64) ([]byte, error) {
	if err := decodeResponse(res); err != nil {
		return nil, err
	}
	return readBounded(res.Body, limit)
}

func (c *apiClient) get(ctx context.Context, path string, q url.Values) ([]byte, string, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", c.endpoint(path, q), nil)
	if e != nil {
		return nil, "", e
	}
	req.Header = c.headers.Clone()
	if path == "attestation/report" && (c.direct || !q.Has("model")) {
		for _, name := range []string{"Authorization", "Api-Key", "X-Api-Key"} {
			req.Header.Del(name)
		}
	}
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
		return nil, "", &Error{
			Code:      "api.http_status",
			Details:   map[string]any{"status": res.StatusCode},
			Retryable: res.StatusCode == 408 || res.StatusCode == 425 || res.StatusCode == 429 || res.StatusCode >= 500,
		}
	}
	b, e := readResponseBounded(res, 16<<20)
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
		if o.SigningAlgo == "" {
			address, e := unhex(o.SigningAddress)
			if e != nil || (len(address) != 20 && len(address) != 32) {
				return nil, failure("api.invalid_input", e)
			}
		} else if _, e := signingBytes(SigningIdentity{o.SigningAlgo, o.SigningAddress}); e != nil {
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
	return c.fetchModelAttestations(ctx, model, o)
}

func (c *DirectAttestationClient) FetchModelAttestations(ctx context.Context, o FetchOptions) (FetchedModelAttestations, error) {
	return c.fetchModelAttestations(ctx, "", o)
}

func (c *apiClient) fetchModelAttestations(ctx context.Context, model string, o FetchOptions) (FetchedModelAttestations, error) {
	var out FetchedModelAttestations
	q, e := optionsQuery(o)
	if e != nil {
		return out, e
	}
	n := nonce()
	q.Set("nonce", n)
	includeTLS := c.direct && !o.DisableTLSBinding
	q.Set("include_tls_fingerprint", fmt.Sprint(includeTLS))
	if !c.direct {
		if model == "" {
			return out, failure("api.invalid_input", nil)
		}
		q.Set("model", model)
		q.Set("provider", "near")
	}
	b, fp, e := c.get(ctx, "attestation/report", q)
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
		if !sameHex(a.Nonce, n) || (a.SPKIFingerprint != "") != includeTLS || (c.direct && a.ModelName == "") {
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
			candidate := a
			candidate.ComposeManagerAttestation = nil
			report := out.Attestations[i]
			report.ComposeManagerAttestation = nil
			if sameAttestation(candidate, report) {
				if out.Attestations[i].ComposeManagerAttestation == nil {
					out.Attestations[i].ComposeManagerAttestation = a.ComposeManagerAttestation
				}
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
	if includeTLS {
		if fp == "" {
			return out, failure("binding.spki_fingerprint_required", nil)
		}
		out.ClientBinding.SPKIFingerprint = fp
	}
	return out, nil
}

func (c *apiClient) FetchCompletionSignature(ctx context.Context, id string, algo SigningAlgo) (CompletionSignature, error) {
	var sig CompletionSignature
	if id == "" || id == "." || id == ".." {
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
		return sig, &Error{
			Code:    "api.completion_signature_unavailable",
			Details: map[string]any{"providerErrorCode": raw.ErrorCode, "providerMessage": raw.Message},
		}
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
		Manager   *ComposeManagerAttestation `json:"compose_manager_attestation"`
		Report    string                     `json:"report_data"`
		PublicKey string                     `json:"signing_public_key"`
		GPU       *string                    `json:"nvidia_payload"`
		FP        string                     `json:"tls_cert_fingerprint"`
		Model     string                     `json:"model_name"`
	}
	if e := json.Unmarshal(data, &raw); e != nil {
		return a, failure("api.invalid_response", e)
	}
	if raw.Manager != nil && (raw.Manager.Actions == nil || raw.Manager.Nonce == "" || raw.Manager.IntelQuote == "" || len(raw.Manager.EventLog) == 0 || raw.Manager.ActionsHash == "") {
		return a, failure("api.invalid_response", nil)
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
	a = Attestation{
		ComposeManagerAttestation: raw.Manager,
		Nonce:                     raw.Nonce,
		Signer:                    SigningIdentity{raw.Algo, raw.Address},
		IntelQuote:                raw.Quote,
		EventLog:                  raw.EventLog,
		AppCompose:                *tcb.Compose,
		ReportedQuoteData:         raw.Report,
		SigningPublicKey:          raw.PublicKey,
		NvidiaPayload:             raw.GPU,
		SPKIFingerprint:           raw.FP,
		ModelName:                 raw.Model,
		InstanceID:                raw.Info.InstanceID,
	}
	if _, e := hexSize(a.Nonce, 32); e != nil {
		return a, failure("api.invalid_response", e)
	}
	if _, e := signingBytes(a.Signer); e != nil {
		return a, failure("api.invalid_response", e)
	}
	return a, nil
}

// NewPinnedTransport clones a standard HTTP transport and requires one of the
// verified SPKI fingerprints during TLS handshake, before request bytes are sent.
func NewPinnedTransport(base *http.Transport, fingerprints ...string) (*http.Transport, error) {
	if len(fingerprints) == 0 {
		return nil, failure("api.invalid_input", nil)
	}
	expected := make(map[string]bool, len(fingerprints))
	for _, fingerprint := range fingerprints {
		value, err := hexSize(fingerprint, 32)
		if err != nil {
			return nil, err
		}
		expected[hex.EncodeToString(value)] = true
	}
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	if base.DialTLSContext != nil || base.DialTLS != nil {
		return nil, failure("api.invalid_input", nil)
	}
	t := base.Clone()
	// Proxy selection runs before dialing, including when a connection is reused.
	proxy := t.Proxy
	t.Proxy = func(req *http.Request) (*url.URL, error) {
		if req.URL.Scheme != "https" {
			return nil, detail("api.invalid_input", "expected", "HTTPS for pinned TLS")
		}
		if proxy == nil {
			return nil, nil
		}
		return proxy(req)
	}
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
		if !expected[hex.EncodeToString(sum[:])] {
			return failure("binding.spki_fingerprint_mismatch", nil)
		}
		return nil
	}
	return t, nil
}

// FindModelAttestationsForSignature returns every verified report sharing the
// response signer. Use VerifyModelResponse to verify the response signature.
func FindModelAttestationsForSignature(items []VerifiedModelAttestation, sig CompletionSignature) ([]VerifiedModelAttestation, error) {
	var matches []VerifiedModelAttestation
	if sig.Kind != "provider_tee" {
		return nil, failure("api.invalid_input", nil)
	}
	for _, a := range items {
		if a.Signer.SigningAlgo == sig.Signer.SigningAlgo && sameHex(a.Signer.SigningAddress, sig.Signer.SigningAddress) {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		return nil, detail("api.model_attestation_not_found", "matches", 0)
	}
	return matches, nil
}

// FindModelAttestationForSignature returns the first report matching the response signer.
//
// Deprecated: use FindModelAttestationsForSignature to support shared signers.
func FindModelAttestationForSignature(items []VerifiedModelAttestation, sig CompletionSignature) (VerifiedModelAttestation, error) {
	matches, err := FindModelAttestationsForSignature(items, sig)
	if err != nil {
		return VerifiedModelAttestation{}, err
	}
	return matches[0], nil
}

// Compare parsed event logs so JSON whitespace/key ordering cannot affect routing.
// UseNumber preserves large integer values, and arrays remain ordered.
func sameAttestation(a, b Attestation) bool {
	parse := func(raw json.RawMessage) (any, error) {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var value any
		err := d.Decode(&value)
		return value, err
	}
	x, ex := parse(a.EventLog)
	y, ey := parse(b.EventLog)
	a.EventLog, b.EventLog = nil, nil
	return ex == nil && ey == nil && reflect.DeepEqual(a, b) && reflect.DeepEqual(x, y)
}
