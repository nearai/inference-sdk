package nearai

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func unhex(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if s == "" {
		return nil, fmt.Errorf("empty hex")
	}
	return hex.DecodeString(s)
}
func hexSize(s string, n int) ([]byte, error) {
	b, e := unhex(s)
	if e != nil || len(b) != n {
		return nil, failure("input.invalid", e)
	}
	return b, nil
}
func sameHex(a, b string) bool {
	x, e := unhex(a)
	y, f := unhex(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func signingBytes(s SigningIdentity) ([]byte, error) {
	switch s.SigningAlgo {
	case Ed25519:
		return hexSize(s.SigningAddress, 32)
	case ECDSA:
		return hexSize(s.SigningAddress, 20)
	default:
		return nil, failure("input.invalid", nil)
	}
}
func keccak(b []byte) []byte   { h := sha3.NewLegacyKeccak256(); h.Write(b); return h.Sum(nil) }
func hashText(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func VerifyModelResponse(request, response []byte, signature CompletionSignature, attestation VerifiedAttestation) error {
	var body struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(request, &body) != nil || body.Model == "" {
		return failure("input.invalid", nil)
	}
	return verifyResponse(signature, "provider_tee", body.Model+":"+hashText(request)+":"+hashText(response), attestation.Signer)
}
func VerifyGatewayResponse(request, response []byte, signature CompletionSignature, attestation VerifiedAttestation) error {
	return verifyResponse(signature, "gateway", hashText(request)+":"+hashText(response), attestation.Signer)
}
func verifyResponse(sig CompletionSignature, kind, text string, signer SigningIdentity) error {
	if sig.Kind != kind {
		return failure("signature.kind_mismatch", nil)
	}
	if sig.SignedText != text {
		return failure("signature.payload_mismatch", nil)
	}
	if sig.Signer.SigningAlgo != signer.SigningAlgo || !sameHex(sig.Signer.SigningAddress, signer.SigningAddress) {
		return failure("signature.signer_mismatch", nil)
	}
	key, e := signingBytes(signer)
	if e != nil {
		return e
	}
	raw, e := unhex(sig.Signature)
	if e != nil {
		return failure("signature.invalid", e)
	}
	switch signer.SigningAlgo {
	case Ed25519:
		if len(raw) != 64 || !ed25519.Verify(key, []byte(text), raw) {
			return failure("signature.invalid", nil)
		}
	case ECDSA:
		if len(raw) != 65 || (raw[64] != 27 && raw[64] != 28 && raw[64] != 0 && raw[64] != 1) {
			return failure("signature.invalid", nil)
		}
		rec := raw[64]
		if rec < 27 {
			rec += 27
		}
		compact := append([]byte{rec}, raw[:64]...)
		digest := keccak([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len([]byte(text)), text)))
		pub, _, err := secpecdsa.RecoverCompact(compact, digest)
		if err != nil || !bytes.Equal(keccak(pub.SerializeUncompressed()[1:])[12:], key) {
			return failure("signature.invalid", err)
		}
	}
	return nil
}

// VerifyGatewayAttestation verifies quote, nonce, deployment measurements and
// (when advertised) the observed TLS peer's SHA-256 SPKI fingerprint.
func VerifyGatewayAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions) (VerifiedAttestation, error) {
	v, e := verifyAttestation(ctx, a, b, o, true)
	if e != nil {
		return v, e
	}
	if a.SPKIFingerprint != "" && !sameHex(a.SPKIFingerprint, b.SPKIFingerprint) {
		return VerifiedAttestation{}, failure("binding.spki_fingerprint_mismatch", nil)
	}
	return v, nil
}
func VerifyModelAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions) (VerifiedAttestation, error) {
	if a.SPKIFingerprint != "" {
		return VerifiedAttestation{}, failure("input.invalid", nil)
	}
	return verifyAttestation(ctx, a, b, o, false)
}

// VerifyDirectModelAttestation authenticates an individual direct model report.
// Its fingerprint is quote-bound but is not a claim about the observed TLS peer.
func VerifyDirectModelAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions) (VerifiedAttestation, error) {
	return verifyAttestation(ctx, a, b, o, false)
}
func verifyAttestation(ctx context.Context, a Attestation, b ClientBinding, o VerificationOptions, gateway bool) (VerifiedAttestation, error) {
	var v VerifiedAttestation
	nonce, e := hexSize(b.Nonce, 32)
	if e != nil {
		return v, e
	}
	if !sameHex(a.Nonce, b.Nonce) {
		return v, failure("binding.nonce_mismatch", nil)
	}
	signer, e := signingBytes(a.Signer)
	if e != nil {
		return v, e
	}
	verifier := o.QuoteVerifier
	if verifier == nil {
		verifier = CreateTDXQuoteVerifier("")
	}
	q, e := verifier(ctx, a.IntelQuote)
	if e != nil {
		return v, failure("quote.verification_failed", e)
	}
	if len(q.ReportData) != 64 || len(q.MRConfigID) != 48 || len(q.RTMR3) != 48 {
		return v, failure("quote.invalid_result", nil)
	}
	validStatus := false
	for _, status := range []string{"UpToDate", "OutOfDate", "Revoked", "ConfigurationNeeded", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded"} {
		if q.TCBStatus == status {
			validStatus = true
		}
	}
	if !validStatus {
		return v, failure("quote.invalid_result", nil)
	}
	if q.DebugEnabled {
		return v, failure("policy.debug_enabled", nil)
	}
	statuses := o.Policy.AcceptedTCBStatuses
	if statuses == nil {
		statuses = []string{"UpToDate", "OutOfDate"}
	}
	allowed := false
	for _, s := range statuses {
		if s == q.TCBStatus {
			allowed = true
		}
	}
	if !allowed {
		return v, detail("policy.tcb_status_not_allowed", "actual", q.TCBStatus)
	}
	if !bytes.Equal(nonce, q.ReportData[32:]) {
		return v, failure("binding.nonce_mismatch", nil)
	}
	if a.ReportedQuoteData != "" {
		advertised, e := hexSize(a.ReportedQuoteData, 64)
		if e != nil || !bytes.Equal(advertised, q.ReportData) {
			return v, failure("binding.report_data_mismatch", e)
		}
	}
	binding := make([]byte, 32)
	copy(binding, signer)
	if a.SPKIFingerprint != "" {
		fp, e := hexSize(a.SPKIFingerprint, 32)
		if e != nil {
			return v, e
		}
		h := sha256.Sum256(append(signer, fp...))
		binding = h[:]
	}
	if !bytes.Equal(binding, q.ReportData[:32]) {
		return v, failure("binding.report_data_mismatch", nil)
	}
	compose := sha256.Sum256([]byte(a.AppCompose))
	if q.MRConfigID[0] != 1 || !bytes.Equal(q.MRConfigID[1:33], compose[:]) {
		return v, failure("measurement.app_compose_mrconfigid_mismatch", nil)
	}
	measurements, e := replayEvents(a.EventLog, q.RTMR3)
	if e != nil {
		return v, e
	}
	v = VerifiedAttestation{Signer: a.Signer, TCBStatus: q.TCBStatus, AdvisoryIDs: append([]string(nil), q.AdvisoryIDs...), Deployment: MeasuredDeployment{a.AppCompose, measurements}, DeploymentProvenance: "not_checked", SPKIFingerprint: a.SPKIFingerprint, ModelName: a.ModelName, InstanceID: a.InstanceID}
	if o.DeploymentVerifier != nil {
		if e = o.DeploymentVerifier(ctx, v.Deployment); e != nil {
			return VerifiedAttestation{}, failure("provenance.verification_failed", e)
		}
		v.DeploymentProvenance = "verified"
	}
	if !gateway {
		v.GPUEvidence = "not_provided"
		if a.NvidiaPayload == nil {
			if o.Policy.RequireGPUEvidence {
				return VerifiedAttestation{}, failure("policy.gpu_evidence_required", nil)
			}
		} else {
			var p struct {
				Nonce string `json:"nonce"`
			}
			if json.Unmarshal([]byte(*a.NvidiaPayload), &p) != nil || !sameHex(p.Nonce, b.Nonce) {
				return VerifiedAttestation{}, failure("binding.nonce_mismatch", nil)
			}
			gpu := o.GPUVerifier
			if gpu == nil {
				gpu = CreateGPUEvidenceVerifier(GPUVerifierOptions{})
			}
			if e = gpu(ctx, *a.NvidiaPayload); e != nil {
				return VerifiedAttestation{}, e
			}
			v.GPUEvidence = "verified"
		}
		if a.SigningPublicKey != "" {
			pub, e := unhex(a.SigningPublicKey)
			if e != nil {
				return VerifiedAttestation{}, e
			}
			switch a.Signer.SigningAlgo {
			case Ed25519:
				if !bytes.Equal(pub, signer) {
					return VerifiedAttestation{}, failure("binding.model_public_key_mismatch", nil)
				}
			case ECDSA:
				if len(pub) == 64 {
					pub = append([]byte{4}, pub...)
				}
				parsed, e := secp.ParsePubKey(pub)
				if e != nil || len(pub) != 65 || !bytes.Equal(keccak(parsed.SerializeUncompressed()[1:])[12:], signer) {
					return VerifiedAttestation{}, failure("binding.model_public_key_mismatch", e)
				}
				pub = pub[1:]
			}
			v.SigningPublicKey = hex.EncodeToString(pub)
		}
	}
	return v, ctx.Err()
}
func replayEvents(raw json.RawMessage, expected []byte) (RuntimeMeasurements, error) {
	var result RuntimeMeasurements
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		raw = []byte(encoded)
	}
	var entries []struct {
		IMR     *uint32 `json:"imr"`
		Type    uint32  `json:"event_type"`
		Event   string  `json:"event"`
		Payload string  `json:"event_payload"`
		Digest  *string `json:"digest"`
	}
	if json.Unmarshal(raw, &entries) != nil || entries == nil {
		return result, failure("measurement.event_log_invalid", nil)
	}
	replay := make([]byte, 48)
	count := 0
	for _, entry := range entries {
		if entry.IMR == nil || entry.Digest == nil {
			return result, failure("measurement.event_log_invalid", nil)
		}
		if *entry.IMR != 3 {
			continue
		}
		count++
		var digest []byte
		if entry.Type == 0x08000001 {
			var payload []byte
			var e error
			if entry.Payload != "" {
				payload, e = unhex(entry.Payload)
			}
			if e != nil {
				return result, failure("measurement.event_log_invalid", e)
			}
			data := make([]byte, 4)
			binary.LittleEndian.PutUint32(data, entry.Type)
			data = append(data, []byte(":"+entry.Event+":")...)
			data = append(data, payload...)
			h := sha512.Sum384(data)
			digest = h[:]
			if *entry.Digest != "" && !sameHex(*entry.Digest, hex.EncodeToString(digest)) {
				return result, failure("measurement.event_log_invalid", nil)
			}
			if entry.Event == "os-image-hash" {
				result.OSImageHash = entry.Payload
			}
			if entry.Event == "compose-hash" {
				result.ComposeHash = entry.Payload
			}
		} else {
			var e error
			digest, e = hexSize(*entry.Digest, 48)
			if e != nil {
				return result, failure("measurement.event_log_invalid", e)
			}
		}
		h := sha512.Sum384(append(replay, digest...))
		replay = h[:]
	}
	if count == 0 || !bytes.Equal(replay, expected) {
		return result, failure("measurement.rtmr3_mismatch", nil)
	}
	return result, nil
}
func VerifyOHTTPKeyConfig(a OHTTPAttestation, signer SigningIdentity) ([]byte, error) {
	if a.SigningAlgo != Ed25519 || signer.SigningAlgo != Ed25519 || !sameHex(a.SigningKey, signer.SigningAddress) {
		return nil, failure("ohttp.signer_mismatch", nil)
	}
	key, e := hexSize(a.SigningKey, 32)
	if e != nil {
		return nil, e
	}
	config, e := unhex(a.KeyConfig)
	if e != nil {
		return nil, e
	}
	sig, e := hexSize(a.Signature, 64)
	if e != nil || !ed25519.Verify(key, config, sig) {
		return nil, failure("ohttp.signature_invalid", e)
	}
	return config, nil
}
