package nearai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

type session struct {
	result    AttestationVerificationResult
	selected  *VerifiedAttestation
	api       *AttestationClient
	transport http.RoundTripper
	expires   time.Time
}
type pendingSession struct {
	done  chan struct{}
	value *session
	err   error
}
type responseRecord struct {
	request, response []byte
	session           *session
	expires           time.Time
	verifying         *pendingResponse
}
type pendingResponse struct {
	done  chan struct{}
	value VerifiedCompletionResult
	err   error
}

// InferenceClient implements http.RoundTripper for OpenAI-compatible Chat
// Completions. Always Close it when finished. Verification precedes transmission;
// callers must explicitly VerifyResponse after consuming a completion or stream.
type InferenceClient struct {
	options                     InferenceOptions
	api                         *AttestationClient
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	sessions                    map[string]*session
	pending                     map[string]*pendingSession
	responses                   map[string]*responseRecord
	transports                  map[string]*http.Transport
	wg                          sync.WaitGroup
	closed                      bool
	attestationTTL, responseTTL time.Duration
	maxBody                     int64
}

func NewInferenceClient(o InferenceOptions) (*InferenceClient, error) {
	return newInferenceClient(o, false)
}

// NewDirectInferenceClient is experimental: no Gateway or direct TLS attestation
// binding. E2EE defaults to true; DisableE2EE explicitly opts out.
func NewDirectInferenceClient(o DirectInferenceOptions) (*InferenceClient, error) {
	o.InferenceOptions.E2EE = !o.DisableE2EE
	return newInferenceClient(o.InferenceOptions, true)
}
func newInferenceClient(o InferenceOptions, direct bool) (*InferenceClient, error) {
	if o.SigningAlgo == "" {
		o.SigningAlgo = Ed25519
	}
	if (o.SigningAlgo != Ed25519 && o.SigningAlgo != ECDSA) || (o.OHTTP && o.SigningAlgo != Ed25519) {
		return nil, failure("api.invalid_input", nil)
	}
	a, e := newAPIClient(o.ClientOptions, direct)
	if e != nil {
		return nil, e
	}
	at, rt := time.Hour, time.Hour
	if o.AttestationTTL != nil {
		at = *o.AttestationTTL
	}
	if o.ResponseTTL != nil {
		rt = *o.ResponseTTL
	}
	if at < 0 || rt < 0 || o.MaxBodyBytes < 0 {
		return nil, failure("api.invalid_input", nil)
	}
	if o.MaxBodyBytes == 0 {
		o.MaxBodyBytes = 64 << 20
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &InferenceClient{options: o, api: a, ctx: ctx, cancel: cancel, sessions: map[string]*session{}, pending: map[string]*pendingSession{}, responses: map[string]*responseRecord{}, transports: map[string]*http.Transport{}, attestationTTL: at, responseTTL: rt, maxBody: o.MaxBodyBytes}
	// Expiry also runs while idle so sensitive retained bodies do not linger.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				c.mu.Lock()
				c.prune(now)
				c.mu.Unlock()
			}
		}
	}()
	return c, nil
}
func (c *InferenceClient) prune(now time.Time) {
	for k, v := range c.sessions {
		if !now.Before(v.expires) {
			delete(c.sessions, k)
		}
	}
	for k, v := range c.responses {
		if !now.Before(v.expires) {
			delete(c.responses, k)
		}
	}
}

// HTTPClient returns an adapter that can be supplied to openai-go WithHTTPClient.
func (c *InferenceClient) HTTPClient() *http.Client {
	return &http.Client{Transport: c, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (c *InferenceClient) BaseURL() string { return c.api.base.String() }
func (c *InferenceClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	c.sessions = map[string]*session{}
	c.responses = map[string]*responseRecord{}
	transports := c.transports
	c.mu.Unlock()
	for _, t := range transports {
		t.CloseIdleConnections()
	}
	c.wg.Wait()
	return nil
}
func cloneResult(r AttestationVerificationResult) AttestationVerificationResult {
	clone := func(a VerifiedAttestation) VerifiedAttestation {
		a.AdvisoryIDs = append([]string(nil), a.AdvisoryIDs...)
		return a
	}
	if r.Gateway != nil {
		v := clone(*r.Gateway)
		r.Gateway = &v
	}
	r.Models = append([]VerifiedAttestation(nil), r.Models...)
	for i := range r.Models {
		r.Models[i] = clone(r.Models[i])
	}
	return r
}
func (c *InferenceClient) Verify(ctx context.Context, model string) (AttestationVerificationResult, error) {
	s, e := c.getSession(ctx, model)
	if e != nil {
		return AttestationVerificationResult{}, e
	}
	return cloneResult(s.result), nil
}
func (c *InferenceClient) getSession(ctx context.Context, model string) (*session, error) {
	if model == "" {
		return nil, failure("api.invalid_input", nil)
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, failure("api.client_closed", nil)
	}
	if s := c.sessions[model]; s != nil && time.Now().Before(s.expires) {
		c.mu.Unlock()
		return s, nil
	}
	p := c.pending[model]
	if p == nil {
		p = &pendingSession{done: make(chan struct{})}
		c.pending[model] = p
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
			defer cancel()
			s, e := c.createSession(ctx, model)
			c.mu.Lock()
			defer c.mu.Unlock()
			p.value, p.err = s, e
			delete(c.pending, model)
			if e == nil && !c.closed && c.attestationTTL > 0 {
				s.expires = time.Now().Add(c.attestationTTL)
				c.sessions[model] = s
			}
			close(p.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, failure("api.client_closed", nil)
	case <-p.done:
		return p.value, p.err
	}
}
func (c *InferenceClient) createSession(ctx context.Context, model string) (*session, error) {
	o := c.options
	s := &session{api: c.api}
	transport := c.api.http.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	s.transport = transport
	opts := o.ModelVerification
	original := opts.DeploymentVerifier
	if o.DeploymentPolicy != nil {
		opts.DeploymentVerifier = func(ctx context.Context, d MeasuredDeployment) error {
			if original != nil {
				if e := original(ctx, d); e != nil {
					return e
				}
			}
			return o.DeploymentPolicy(ctx, model, d)
		}
	}
	var models FetchedModelAttestations
	var ohttp *OHTTPAttestation
	var ohttpSigner SigningIdentity
	if c.api.direct {
		var e error
		models, e = c.api.FetchModelAttestations(ctx, model, FetchOptions{SigningAlgo: o.SigningAlgo})
		if e != nil {
			return nil, e
		}
		ohttp = models.OHTTPAttestation
	} else {
		fetched, e := c.api.FetchGatewayAttestation(ctx, FetchOptions{SigningAlgo: o.SigningAlgo, DisableTLSBinding: o.DisableTLSBinding})
		if e != nil {
			return nil, e
		}
		verified, e := VerifyGatewayAttestation(ctx, fetched.Attestation, fetched.ClientBinding, o.GatewayVerification)
		if e != nil {
			return nil, e
		}
		if verified.Signer.SigningAlgo != o.SigningAlgo {
			return nil, failure("signature.signer_mismatch", nil)
		}
		s.result.Gateway = &verified
		ohttp = fetched.OHTTPAttestation
		ohttpSigner = verified.Signer
		if !o.DisableTLSBinding {
			base, ok := transport.(*http.Transport)
			if !ok {
				return nil, detail("api.invalid_input", "reason", "TLS pinning requires *http.Transport")
			}
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return nil, failure("api.client_closed", nil)
			}
			pinned := c.transports[verified.SPKIFingerprint]
			if pinned == nil {
				pinned, e = NewPinnedTransport(base, verified.SPKIFingerprint)
				if e != nil {
					c.mu.Unlock()
					return nil, e
				}
				// Bound pools across Gateway key rotations. Eviction closes idle
				// sockets; sessions still holding a pool may finish normally.
				if len(c.transports) >= 16 {
					for key, old := range c.transports {
						old.CloseIdleConnections()
						delete(c.transports, key)
						break
					}
				}
				c.transports[verified.SPKIFingerprint] = pinned
			}
			c.mu.Unlock()
			s.transport = pinned
			api := *c.api
			client := *c.api.http
			client.Transport = pinned
			api.http = &client
			s.api = &api
		}
		metadata, e := s.api.FetchModelMetadata(ctx, model)
		if e != nil {
			return nil, e
		}
		if metadata.ProviderType == "vllm" && metadata.AttestationSupported {
			models, e = s.api.FetchModelAttestations(ctx, model, FetchOptions{SigningAlgo: o.SigningAlgo})
			if e != nil {
				return nil, e
			}
			if len(models.Attestations) == 0 {
				return nil, failure("policy.model_attestation_required", nil)
			}
		} else if o.E2EE || o.DeploymentPolicy != nil || opts.DeploymentVerifier != nil || opts.Policy.AcceptedTCBStatuses != nil || opts.Policy.RequireGPUEvidence {
			return nil, failure("policy.model_attestation_required", nil)
		}
	}
	for _, report := range models.Attestations {
		var verified VerifiedAttestation
		var e error
		if c.api.direct {
			verified, e = VerifyDirectModelAttestation(ctx, report, models.ClientBinding, opts)
		} else {
			verified, e = VerifyModelAttestation(ctx, report, models.ClientBinding, opts)
		}
		if e != nil {
			return nil, e
		}
		s.result.Models = append(s.result.Models, verified)
		if c.api.direct && models.ServingAttestation != nil && reflect.DeepEqual(report, *models.ServingAttestation) {
			ohttpSigner = verified.Signer
		}
		if s.selected == nil && verified.Signer.SigningAlgo == o.SigningAlgo && verified.SigningPublicKey != "" && (!c.api.direct || !o.OHTTP || (models.ServingAttestation != nil && verified.Signer.SigningAlgo == models.ServingAttestation.Signer.SigningAlgo && sameHex(verified.Signer.SigningAddress, models.ServingAttestation.Signer.SigningAddress))) {
			copy := verified
			s.selected = &copy
		}
	}
	if len(s.result.Models) > 0 && s.selected == nil {
		return nil, failure("e2ee.model_public_key_required", nil)
	}
	if c.api.direct && len(s.result.Models) == 0 {
		return nil, failure("policy.model_attestation_required", nil)
	}
	if o.OHTTP {
		if ohttp == nil {
			return nil, failure("ohttp.attestation_required", nil)
		}
		config, e := VerifyOHTTPKeyConfig(*ohttp, ohttpSigner)
		if e != nil {
			return nil, e
		}
		s.transport, e = NewOHTTPTransport(config, c.BaseURL(), s.transport, headerNames(c.api.headers))
		if e != nil {
			return nil, e
		}
	}
	s.result.VerifiedAt = time.Now()
	return s, nil
}
func headerNames(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// RoundTrip only accepts POSTs to this client's configured Chat endpoint.
func (c *InferenceClient) RoundTrip(req *http.Request) (*http.Response, error) {
	expected := *c.api.base
	expected.Path += "chat/completions"
	u := *req.URL
	u.RawQuery = ""
	u.ForceQuery = false
	if req.Method != "POST" || u.String() != expected.String() || req.Body == nil {
		return nil, failure("api.invalid_input", nil)
	}
	defer req.Body.Close()
	body, e := readBounded(req.Body, c.maxBody)
	if e != nil {
		return nil, e
	}
	parsed, e := decodeObject(body)
	if e != nil {
		return nil, e
	}
	model, ok := parsed["model"].(string)
	if !ok || model == "" {
		return nil, failure("api.invalid_input", nil)
	}
	s, e := c.getSession(req.Context(), model)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(c.ctx, cancel)
	r := req.Clone(ctx)
	r.Header = c.api.headers.Clone()
	for k, v := range req.Header {
		r.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	if auth := c.api.headers.Get("Authorization"); auth != "" {
		r.Header.Set("Authorization", auth)
	} else {
		r.Header.Del("Authorization")
	}
	if c.options.APIKey != "" {
		r.Header.Del("Api-Key")
	}
	removeE2EEHeaders(r.Header)
	removeBodyHeaders(r.Header)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(NoAliasingHeader, "true")
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Trailer = nil
	var prepared *PreparedE2EEChatRequest
	if c.options.E2EE {
		if s.selected == nil {
			stop()
			cancel()
			return nil, failure("policy.model_attestation_required", nil)
		}
		prepared, e = PrepareE2EEChatRequest(r, E2EEModelKey{c.options.SigningAlgo, s.selected.SigningPublicKey})
		if e != nil {
			stop()
			cancel()
			return nil, e
		}
		r = prepared.Request
		body, e = readBounded(r.Body, c.maxBody)
		if e != nil {
			stop()
			cancel()
			return nil, e
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	} else if s.selected != nil {
		r.Header.Set("X-Model-Pub-Key", s.selected.SigningPublicKey)
	}
	response, e := s.transport.RoundTrip(r)
	if e != nil {
		stop()
		cancel()
		return nil, e
	}
	source := &cancelBody{ReadCloser: response.Body, cancel: func() { stop(); cancel() }}
	response.Body = source
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response, nil
	}
	streaming := strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
	if !streaming {
		defer source.Close()
		wire, e := readBounded(source, c.maxBody)
		if e != nil {
			return nil, e
		}
		obj, e := decodeObject(wire)
		if e != nil {
			return nil, e
		}
		id, ok := obj["id"].(string)
		if !ok || id == "" {
			return nil, failure("api.invalid_response", nil)
		}
		visible := wire
		if prepared != nil {
			visible, e = prepared.DecryptJSON(wire)
			if e != nil {
				return nil, e
			}
		}
		if e = c.register(id, body, wire, s); e != nil {
			return nil, e
		}
		response.Body = io.NopCloser(bytes.NewReader(visible))
		removeBodyHeaders(response.Header)
		response.ContentLength = int64(len(visible))
		return response, nil
	}
	capture := &captureReader{ReadCloser: source, limit: c.maxBody}
	id := ""
	failed := false
	transform := func(record []byte) ([]byte, error) {
		data, event := sseData(record)
		if event == "error" {
			failed = true
		}
		if data != "" && data != "[DONE]" && event != "error" {
			obj, e := decodeObject([]byte(data))
			if e != nil {
				return nil, e
			}
			if _, ok := obj["error"]; ok {
				failed = true
			}
			if candidate, ok := obj["id"].(string); ok && candidate != "" {
				if id != "" && candidate != id {
					return nil, failure("api.invalid_response", nil)
				}
				id = candidate
			}
		}
		if prepared != nil {
			return prepared.transformSSE(record)
		}
		return record, nil
	}
	finish := func() error {
		if failed || id == "" {
			return failure("api.invalid_response", nil)
		}
		return c.register(id, body, capture.body.Bytes(), s)
	}
	response.Body = &sseReader{source: capture, reader: bufio.NewReader(capture), transform: transform, finish: finish, limit: c.maxBody}
	removeBodyHeaders(response.Header)
	response.ContentLength = -1
	return response, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel func()
	once   sync.Once
}

func (b *cancelBody) Close() error { e := b.ReadCloser.Close(); b.once.Do(b.cancel); return e }
func (c *InferenceClient) register(id string, request, response []byte, s *session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return failure("api.client_closed", nil)
	}
	if existing := c.responses[id]; existing != nil && time.Now().Before(existing.expires) {
		return failure("api.duplicate_completion_id", nil)
	}
	c.responses[id] = &responseRecord{request: append([]byte(nil), request...), response: append([]byte(nil), response...), session: s, expires: time.Now().Add(c.responseTTL)}
	return nil
}
func (c *InferenceClient) VerifyResponse(ctx context.Context, id string) (VerifiedCompletionResult, error) {
	c.mu.Lock()
	record := c.responses[id]
	if record == nil || !time.Now().Before(record.expires) {
		c.mu.Unlock()
		return VerifiedCompletionResult{}, failure("api.completion_not_found", nil)
	}
	p := record.verifying
	if p == nil {
		p = &pendingResponse{done: make(chan struct{})}
		record.verifying = p
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
			defer cancel()
			value, e := c.verifyRecord(ctx, id, record)
			c.mu.Lock()
			defer c.mu.Unlock()
			p.value, p.err = value, e
			var sdk *Error
			if e != nil && (errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) || (errors.As(e, &sdk) && (sdk.Retryable || sdk.Code == "api.completion_signature_unavailable"))) {
				record.verifying = nil
			}
			close(p.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return VerifiedCompletionResult{}, ctx.Err()
	case <-c.ctx.Done():
		return VerifiedCompletionResult{}, failure("api.client_closed", nil)
	case <-p.done:
		result := p.value
		if result.Attestation != nil {
			a := *result.Attestation
			a.AdvisoryIDs = append([]string(nil), a.AdvisoryIDs...)
			result.Attestation = &a
		}
		result.Attestations = cloneResult(AttestationVerificationResult{Models: result.Attestations}).Models
		return result, p.err
	}
}
func (c *InferenceClient) verifyRecord(ctx context.Context, id string, r *responseRecord) (VerifiedCompletionResult, error) {
	sig, e := r.session.api.FetchCompletionSignature(ctx, id, c.options.SigningAlgo)
	if e != nil {
		return VerifiedCompletionResult{}, e
	}
	if sig.Signer.SigningAlgo != c.options.SigningAlgo {
		return VerifiedCompletionResult{}, failure("signature.signer_mismatch", nil)
	}
	var a *VerifiedAttestation
	if sig.Kind == "gateway" {
		a = r.session.result.Gateway
		if a != nil {
			e = VerifyGatewayResponse(r.request, r.response, sig, *a)
		}
	} else {
		a = r.session.selected
		if a != nil {
			e = VerifyModelResponse(r.request, r.response, sig, *a)
		}
	}
	if a == nil {
		return VerifiedCompletionResult{}, failure("signature.kind_mismatch", nil)
	}
	if e != nil {
		return VerifiedCompletionResult{}, e
	}
	if c.api.direct {
		return VerifyDirectModelResponse(id, r.request, r.response, sig, r.session.result.Models)
	}
	copy := *a
	return VerifiedCompletionResult{CompletionID: id, SignatureKind: sig.Kind, Signature: sig, Attestation: &copy}, nil
}

// CreateChatCompletion accepts ordinary or future OpenAI fields and returns JSON.
// For streaming or typed requests, use HTTPClient with the official Go OpenAI SDK.
func (c *InferenceClient) CreateChatCompletion(ctx context.Context, request any) (json.RawMessage, error) {
	body, e := json.Marshal(request)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.api.endpoint("chat/completions", nil), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	res, e := c.HTTPClient().Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, detail("api.http_status", "status", res.StatusCode)
	}
	return readBounded(res.Body, c.maxBody)
}
