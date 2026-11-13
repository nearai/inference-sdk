package nearai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// inferenceOptions contains only settings shared by both inference clients.
type inferenceOptions struct {
	ClientOptions
	SigningAlgo       SigningAlgo
	E2EE              bool
	OHTTP             bool
	AttestationTTL    *time.Duration
	ResponseTTL       *time.Duration
	ModelVerification VerificationOptions
	DeploymentPolicy  func(context.Context, string, MeasuredDeployment) error
}
type sessionPreflight func(context.Context, *inferenceCore, *session, string) (FetchedModelAttestations, error)

type session struct {
	gateway                    *VerifiedGatewayAttestation
	models                     []VerifiedModelAttestation
	verifiedAt                 time.Time
	direct                     *VerifiedDirectModelAttestations
	selectedDirectAttestations []VerifiedDirectModelAttestation
	selected                   *VerifiedModelAttestation
	api                        *apiClient
	transport                  http.RoundTripper
	expires                    time.Time
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
	gatewayOnly       bool
}
type pendingResponse struct {
	done  chan struct{}
	value verifiedResponse
	err   error
}

// Cached verification outcomes are independent of either public client result.
type verifiedResponse struct {
	id                 string
	signature          CompletionSignature
	attestation        VerifiedCompletionAttestation
	attestations       []VerifiedModelAttestation
	directAttestations []VerifiedDirectModelAttestation
}

// inferenceCore owns shared transport, capture, cache, and cancellation.
type inferenceCore struct {
	options                     inferenceOptions
	preflight                   sessionPreflight
	api                         *apiClient
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	sessions                    map[string]*session
	pending                     map[string]*pendingSession
	responses                   map[string]*responseRecord
	responseGeneration          uint64
	transports                  map[string]*http.Transport
	wg                          sync.WaitGroup
	closed                      bool
	attestationTTL, responseTTL time.Duration
}

func newInferenceCore(o inferenceOptions, direct bool, preflight sessionPreflight) (*inferenceCore, error) {
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
	if at < 0 || rt < 0 {
		return nil, failure("api.invalid_input", nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &inferenceCore{
		preflight:      preflight,
		options:        o,
		api:            a,
		ctx:            ctx,
		cancel:         cancel,
		sessions:       map[string]*session{},
		pending:        map[string]*pendingSession{},
		responses:      map[string]*responseRecord{},
		transports:     map[string]*http.Transport{},
		attestationTTL: at,
		responseTTL:    rt,
	}
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

func (c *inferenceCore) prune(now time.Time) {
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

func (c *inferenceCore) BaseURL() string { return c.api.base.String() }

// ClearResponseCache clears captured response verification records.
func (c *inferenceCore) ClearResponseCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responseGeneration++
	clear(c.responses)
}

func (c *inferenceCore) responseCacheGeneration() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.responseGeneration
}

func (c *inferenceCore) Close() error {
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

func (c *inferenceCore) getSession(ctx context.Context, model string) (*session, error) {
	key := model

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
	if s := c.sessions[key]; s != nil && time.Now().Before(s.expires) {
		c.mu.Unlock()
		return s, nil
	}
	p := c.pending[key]
	if p == nil {
		p = &pendingSession{done: make(chan struct{})}
		c.pending[key] = p
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
			defer cancel()
			s, e := c.createSession(ctx, model)
			c.mu.Lock()
			defer c.mu.Unlock()
			p.value, p.err = s, e
			delete(c.pending, key)
			if e == nil && !c.closed && c.attestationTTL > 0 {
				c.prune(time.Now())
				s.expires = time.Now().Add(c.attestationTTL)
				c.sessions[key] = s
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

func (c *inferenceCore) createSession(ctx context.Context, model string) (*session, error) {
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
	fetchedModelAttestations, err := c.preflight(ctx, c, s, model)
	if err != nil {
		return nil, err
	}
	if c.api.direct {
		verified, err := VerifyDirectModelAttestations(ctx, fetchedModelAttestations, opts)
		if err != nil {
			return nil, err
		}
		s.direct = &verified
		serving := verified.ServingAttestation
		requiresServingSigner := o.OHTTP || serving.SPKIFingerprint != ""
		for _, attestation := range verified.Attestations {
			if attestation.Signer.SigningAlgo == o.SigningAlgo && attestation.SigningPublicKey != "" &&
				(!requiresServingSigner || (attestation.Signer.SigningAlgo == serving.Signer.SigningAlgo && sameHex(attestation.Signer.SigningAddress, serving.Signer.SigningAddress))) {
				selected := attestation.VerifiedModelAttestation
				s.selected = &selected
				break
			}
		}
		if s.selected == nil {
			return nil, failure("e2ee.model_public_key_required", nil)
		}
		for _, attestation := range verified.Attestations {
			if attestation.Signer.SigningAlgo == s.selected.Signer.SigningAlgo && sameHex(attestation.Signer.SigningAddress, s.selected.Signer.SigningAddress) {
				s.selectedDirectAttestations = append(s.selectedDirectAttestations, attestation)
			}
		}
		if err := c.configureDirectSession(s, fetchedModelAttestations); err != nil {
			return nil, err
		}
	} else {
		for _, report := range fetchedModelAttestations.Attestations {
			verified, err := VerifyModelAttestation(ctx, report, fetchedModelAttestations.ClientBinding, opts)
			if err != nil {
				return nil, err
			}
			s.models = append(s.models, verified)
			if s.selected == nil && verified.Signer.SigningAlgo == o.SigningAlgo && verified.SigningPublicKey != "" {
				selected := verified
				s.selected = &selected
			}
		}
		if len(s.models) > 0 && s.selected == nil {
			return nil, failure("e2ee.model_public_key_required", nil)
		}
	}

	s.verifiedAt = time.Now()
	return s, nil
}

func (c *inferenceCore) pinSession(s *session, fingerprints []string) error {
	base, ok := s.transport.(*http.Transport)
	if !ok {
		return detail("api.invalid_input", "reason", "TLS pinning requires *http.Transport")
	}
	key := strings.Join(fingerprints, ",")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return failure("api.client_closed", nil)
	}
	pinned := c.transports[key]
	if pinned == nil {
		var err error
		pinned, err = NewPinnedTransport(base, fingerprints...)
		if err != nil {
			return err
		}
		if len(c.transports) >= 16 {
			for key, old := range c.transports {
				old.CloseIdleConnections()
				delete(c.transports, key)
				break
			}
		}
		c.transports[key] = pinned
	}
	s.transport = pinned
	api := *c.api
	client := *c.api.http
	client.Transport = pinned
	api.http = &client
	s.api = &api
	return nil
}

func (c *inferenceCore) configureOHTTP(s *session, attestation *OHTTPAttestation, signer SigningIdentity) error {
	if !c.options.OHTTP {
		return nil
	}
	if attestation == nil {
		return failure("ohttp.attestation_required", nil)
	}
	config, err := VerifyOHTTPKeyConfig(*attestation, signer)
	if err != nil {
		return err
	}
	s.transport, err = NewOHTTPTransport(config, c.BaseURL(), s.transport, headerNames(c.api.headers))
	return err
}

func headerNames(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// RoundTrip accepts supported inference POSTs on the configured endpoint.
func (c *inferenceCore) RoundTrip(req *http.Request) (*http.Response, error) {
	generation := c.responseCacheGeneration()
	expected := *c.api.base
	expected.Path += "chat/completions"
	responsesURL := *c.api.base
	responsesURL.Path += "responses"
	messagesURL := *c.api.base
	messagesURL.Path += "messages"
	u := *req.URL
	u.RawQuery = ""
	u.ForceQuery = false
	responses := u.String() == responsesURL.String()
	messages := u.String() == messagesURL.String()
	gatewayOnly := responses || messages
	if req.Method != "POST" || (u.String() != expected.String() && !gatewayOnly) || req.Body == nil {
		return nil, failure("api.invalid_input", nil)
	}
	defer req.Body.Close()
	if gatewayOnly && (c.api.direct || c.options.E2EE) {
		return nil, detail("api.invalid_input", "expected", "Gateway Responses or Messages with field-level E2EE disabled")
	}
	body, e := io.ReadAll(req.Body)
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
	r.Host = ""
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
	if messages {
		r.Header.Del("X-Api-Key")
		if key := c.api.headers.Get("X-Api-Key"); key != "" {
			r.Header.Set("X-Api-Key", key)
		}
		if r.Header.Get("Anthropic-Version") == "" {
			r.Header.Set("Anthropic-Version", "2023-06-01")
		}
	}
	removeBodyHeaders(r.Header)
	r.Header.Set("Accept-Encoding", "identity")
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
		body, e = io.ReadAll(r.Body)
		if e != nil {
			stop()
			cancel()
			return nil, e
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	} else if s.selected != nil && !messages {
		r.Header.Set("X-Model-Pub-Key", s.selected.SigningPublicKey)
	}
	// Prevent transport retries after a connection failure, even with an idempotency key.
	r.GetBody = nil
	response, e := s.transport.RoundTrip(r)
	if e != nil {
		stop()
		cancel()
		return nil, e
	}
	response.Body = &cancelBody{ReadCloser: response.Body, cancel: func() { stop(); cancel() }}
	if e = decodeResponse(response); e != nil {
		response.Body.Close()
		return nil, e
	}
	source := response.Body
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response, nil
	}
	streaming := strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
	if !streaming {
		defer source.Close()
		wire, e := io.ReadAll(source)
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
		if e = c.register(id, body, wire, s, gatewayOnly, generation); e != nil {
			return nil, e
		}
		response.Body = io.NopCloser(bytes.NewReader(visible))
		removeBodyHeaders(response.Header)
		response.ContentLength = int64(len(visible))
		return response, nil
	}
	capture := &captureReader{ReadCloser: source}
	id := ""
	failed := false
	messageStarted, messageStopped := false, false
	observe := func(record []byte, data, event string, hasEvent bool) error {
		if messages && (!completeSSERecord(record) || event == "error" || data == "[DONE]") {
			return failure("api.invalid_response", nil)
		}
		if data == "[DONE]" && id == "" {
			return failure("api.invalid_response", nil)
		}
		if event == "error" {
			failed = true
		}
		if data != "" && data != "[DONE]" && event != "error" {
			obj, e := decodeObject([]byte(data))
			if e != nil {
				return e
			}
			if _, ok := obj["error"]; ok {
				failed = true
			}
			if obj["type"] == "error" {
				failed = true
			}
			if messages {
				kind, _ := obj["type"].(string)
				if kind == "" || (hasEvent && event != kind) || messageStopped {
					return failure("api.invalid_response", nil)
				}
				if kind == "message_stop" {
					messageStopped = true
				}
				if kind == "message_start" {
					if messageStarted {
						return failure("api.invalid_response", nil)
					}
					messageStarted = true
					obj, _ = obj["message"].(map[string]any)
				} else {
					obj = nil
				}
			}
			if responses {
				// Output item IDs are not response IDs. Lifecycle events carry
				// the receipt ID inside their response object.
				response, exists := obj["response"]
				if !exists {
					return nil
				}
				obj, _ = response.(map[string]any)
			} else if _, exists := obj["id"]; !exists {
				return nil
			}
			candidate, _ := obj["id"].(string)
			if candidate == "" || (id != "" && candidate != id) {
				return failure("api.invalid_response", nil)
			}
			id = candidate
		}
		return nil
	}
	finish := func() error {
		if failed || id == "" || (messages && !messageStopped) {
			return failure("api.invalid_response", nil)
		}
		return c.register(id, body, capture.body.Bytes(), s, gatewayOnly, generation)
	}
	events := &sseReader{
		source: capture, reader: bufio.NewReader(capture), observe: observe,
		terminal: func() bool { return messages && messageStopped },
		finish:   finish,
	}
	if prepared != nil {
		events.decrypt = prepared.transformSSE
	}
	response.Body = events
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

func (c *inferenceCore) register(id string, request, response []byte, s *session, gatewayOnly bool, generation uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return failure("api.client_closed", nil)
	}
	if generation != c.responseGeneration {
		return nil
	}
	if c.responseTTL == 0 {
		return nil
	}
	if existing := c.responses[id]; existing != nil && time.Now().Before(existing.expires) {
		return failure("api.duplicate_completion_id", nil)
	}
	c.prune(time.Now())
	c.responses[id] = &responseRecord{
		request:     append([]byte(nil), request...),
		response:    append([]byte(nil), response...),
		session:     s,
		gatewayOnly: gatewayOnly,
		expires:     time.Now().Add(c.responseTTL),
	}
	return nil
}

func (c *inferenceCore) verifyResponse(ctx context.Context, id string) (verifiedResponse, error) {
	c.mu.Lock()
	record := c.responses[id]
	if record == nil || !time.Now().Before(record.expires) {
		c.mu.Unlock()
		return verifiedResponse{}, failure("api.completion_not_found", nil)
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
			if e != nil &&
				(errors.Is(e, context.Canceled) ||
					errors.Is(e, context.DeadlineExceeded) ||
					(errors.As(e, &sdk) && (sdk.Retryable || sdk.Code == "api.completion_signature_unavailable"))) {
				record.verifying = nil
			} else {
				// Cached outcomes no longer need the captured wire bytes.
				record.request, record.response, record.session = nil, nil, nil
			}
			close(p.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return verifiedResponse{}, ctx.Err()
	case <-c.ctx.Done():
		return verifiedResponse{}, failure("api.client_closed", nil)
	case <-p.done:
		result := p.value
		result.attestations = slices.Clone(result.attestations)
		result.directAttestations = slices.Clone(result.directAttestations)
		return result, p.err
	}
}

func (c *inferenceCore) verifyRecord(ctx context.Context, id string, r *responseRecord) (verifiedResponse, error) {
	sig, e := r.session.api.FetchCompletionSignature(ctx, id, c.options.SigningAlgo)
	if e != nil {
		return verifiedResponse{}, e
	}
	if sig.Signer.SigningAlgo != c.options.SigningAlgo {
		return verifiedResponse{}, failure("signature.signer_mismatch", nil)
	}
	if r.gatewayOnly && sig.Kind != "gateway" {
		return verifiedResponse{}, failure("signature.kind_mismatch", nil)
	}
	if r.session.direct != nil {
		if err := VerifyDirectModelResponse(r.request, r.response, sig, r.session.selectedDirectAttestations[0]); err != nil {
			return verifiedResponse{}, err
		}
		attestations, err := FindDirectModelAttestationsForSignature(r.session.selectedDirectAttestations, sig)
		if err != nil {
			return verifiedResponse{}, err
		}
		return verifiedResponse{id: id, signature: sig, directAttestations: attestations}, nil
	}
	var attestation VerifiedCompletionAttestation
	var attestations []VerifiedModelAttestation
	if sig.Kind == "gateway" {
		if r.session.gateway == nil {
			return verifiedResponse{}, failure("signature.kind_mismatch", nil)
		}
		if err := VerifyGatewayResponse(r.request, r.response, sig, *r.session.gateway); err != nil {
			return verifiedResponse{}, err
		}
		attestation = r.session.gateway
	} else {
		if r.session.selected == nil {
			return verifiedResponse{}, failure("signature.kind_mismatch", nil)
		}
		if err := VerifyModelResponse(r.request, r.response, sig, *r.session.selected); err != nil {
			return verifiedResponse{}, err
		}
		attestations, e = FindModelAttestationsForSignature(r.session.models, sig)
		if e != nil {
			return verifiedResponse{}, e
		}
		attestation = r.session.selected
	}
	return verifiedResponse{id: id, signature: sig, attestation: attestation, attestations: attestations}, nil
}

// CreateChatCompletion accepts ordinary or future OpenAI fields and returns JSON.
// For streaming or typed requests, use HTTPClient with the official Go OpenAI SDK.
func (c *inferenceCore) CreateChatCompletion(ctx context.Context, request any) (json.RawMessage, error) {
	return c.createJSON(ctx, "chat/completions", request)
}

func (c *inferenceCore) createJSON(ctx context.Context, path string, request any) (json.RawMessage, error) {
	body, e := json.Marshal(request)
	if e != nil {
		return nil, e
	}
	if path == "responses" || path == "messages" {
		parsed, err := decodeObject(body)
		if err != nil {
			return nil, err
		}
		if parsed["stream"] == true {
			return nil, detail("api.invalid_input", "expected", "use HTTPClient for streaming Responses or Messages")
		}
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.api.endpoint(path, nil), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	res, e := (&http.Client{Transport: c, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, detail("api.http_status", "status", res.StatusCode)
	}
	return io.ReadAll(res.Body)
}
