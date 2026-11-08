package nearai

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAttestationRejectsTampering(t *testing.T) {
	tests := []struct {
		name, code string
		mutate     func(*Attestation, *QuoteVerificationResult, *ClientBinding, *VerificationOptions)
	}{
		{
			"nonce",
			"binding.nonce_mismatch",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				b.Nonce = strings.Repeat("cd", 32)
			},
		},
		{
			"quote nonce",
			"binding.nonce_mismatch",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				q.ReportData[63] ^= 1
			},
		},
		{
			"signer",
			"binding.report_data_mismatch",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				q.ReportData[0] ^= 1
			},
		},
		{
			"debug",
			"policy.debug_enabled",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				q.DebugEnabled = true
			},
		},
		{
			"tcb",
			"policy.tcb_status_not_allowed",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				q.TCBStatus = "Revoked"
			},
		},
		{
			"compose",
			"measurement.app_compose_mrconfigid_mismatch",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				a.AppCompose += " "
			},
		},
		{
			"rtmr",
			"measurement.rtmr3_mismatch",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				q.RTMR3[0] ^= 1
			},
		},
		{
			"event",
			"measurement.event_log_invalid",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				a.EventLog = []byte(`[{"imr":3}]`)
			},
		},
		{
			"key",
			"binding.model_public_key_mismatch",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				a.SigningPublicKey = strings.Repeat("11", 32)
			},
		},
		{
			"gpu required",
			"policy.gpu_evidence_required",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				o.Policy.RequireGPUEvidence = true
			},
		},
		{
			"deployment",
			"provenance.verification_failed",
			func(a *Attestation, q *QuoteVerificationResult, b *ClientBinding, o *VerificationOptions) {
				o.DeploymentVerifier = func(context.Context, MeasuredDeployment) error { return errors.New("denied") }
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, q, _ := attestationFixture(t, Ed25519)
			b := ClientBinding{Nonce: a.Nonce}
			o := VerificationOptions{}
			tt.mutate(&a, &q, &b, &o)
			o.QuoteVerifier = fixedQuote(q)
			_, e := VerifyModelAttestation(context.Background(), a, b, o)
			requireCode(t, e, tt.code)
		})
	}
}
func TestModelAttestationSuccess(t *testing.T) {
	a, q, _ := attestationFixture(t, Ed25519)
	o := VerificationOptions{QuoteVerifier: fixedQuote(q)}
	v, e := VerifyModelAttestation(context.Background(), a, ClientBinding{Nonce: a.Nonce}, o)
	if e != nil || v.GPUEvidence != "not_provided" {
		t.Fatalf("%+v %v", v, e)
	}
}

func TestTCBPolicy(t *testing.T) {
	for _, tc := range []struct {
		status            string
		acceptedByDefault bool
	}{
		{"OutOfDate", true},
		{"TDRelaunchAdvised", true},
		{"TDRelaunchAdvisedConfigurationNeeded", false},
		{"Unknown", false},
	} {
		t.Run(tc.status, func(t *testing.T) {
			a, q, _ := attestationFixture(t, Ed25519)
			q.TCBStatus = tc.status
			options := VerificationOptions{QuoteVerifier: fixedQuote(q)}
			binding := ClientBinding{Nonce: a.Nonce}

			_, err := VerifyModelAttestation(context.Background(), a, binding, options)
			if tc.acceptedByDefault {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, "policy.tcb_status_not_allowed")
			}
			options.Policy.AcceptedTCBStatuses = []string{tc.status}
			if _, err := VerifyModelAttestation(context.Background(), a, binding, options); err != nil {
				t.Fatal(err)
			}
			options.Policy.AcceptedTCBStatuses = []string{"UpToDate"}
			_, err = VerifyModelAttestation(context.Background(), a, binding, options)
			requireCode(t, err, "policy.tcb_status_not_allowed")
		})
	}
}
