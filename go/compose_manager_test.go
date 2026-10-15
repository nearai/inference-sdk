package nearai

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

type managerFixture struct {
	Compose     string
	Actions     []ComposeManagerAction
	ActionsHash string `json:"actions_hash"`
}

func loadManagerFixture(t *testing.T) managerFixture {
	t.Helper()
	b, e := os.ReadFile("../test-fixtures/compose-manager/deployment.json")
	if e != nil {
		t.Fatal(e)
	}
	var f managerFixture
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestManagerEvidenceAuthenticatesEverySignedField(t *testing.T) {
	f := loadManagerFixture(t)
	canonical, e := canonicalActions(f.Actions)
	if e != nil || hashText(canonical) != f.ActionsHash {
		t.Fatalf("canonical log mismatch: %s %v", canonical, e)
	}
	a, q, _ := attestationFixture(t, Ed25519)
	managerQuote := q
	managerQuote.ReportData = bytes.Clone(q.ReportData)
	h, _ := hex.DecodeString(f.ActionsHash)
	copy(managerQuote.ReportData, h)
	a.ComposeManagerAttestation = &ComposeManagerAttestation{Actions: f.Actions, ActionsHash: f.ActionsHash, Nonce: a.Nonce, IntelQuote: "bb", EventLog: a.EventLog}
	o := VerificationOptions{QuoteVerifier: func(_ context.Context, raw string) (QuoteVerificationResult, error) {
		if raw == "bb" {
			return managerQuote, nil
		}
		return q, nil
	}}
	verified, e := VerifyModelAttestation(context.Background(), a, ClientBinding{Nonce: a.Nonce}, o)
	if e != nil {
		t.Fatal(e)
	}
	if len(verified.Deployment.ComposeManager.Actions) != 2 {
		t.Fatal("manager evidence missing")
	}
	a.ComposeManagerAttestation.Actions[0]["tag"] = "altered"
	_, e = VerifyModelAttestation(context.Background(), a, ClientBinding{Nonce: a.Nonce}, o)
	requireCode(t, e, "binding.compose_manager_actions_mismatch")
	a.ComposeManagerAttestation.Actions = loadManagerFixture(t).Actions
	a.ComposeManagerAttestation.Nonce = strings.Repeat("aa", 32)
	_, e = VerifyModelAttestation(context.Background(), a, ClientBinding{Nonce: a.Nonce}, o)
	requireCode(t, e, "binding.nonce_mismatch")
	// HTML and Unicode separators must remain exact UTF-8 in the canonical log.
	raw := []byte("[{\"action\":\"x\",\"timestamp\":\"<>&\u2028\u2029\",\"__proto__\":\"signed\",\"10\":\"ten\",\"2\":\"two\"}]")
	var special []ComposeManagerAction
	if e = json.Unmarshal(raw, &special); e != nil {
		t.Fatal(e)
	}
	canonical, e = canonicalActions(special)
	want := []byte("[{\"10\":\"ten\",\"2\":\"two\",\"__proto__\":\"signed\",\"action\":\"x\",\"timestamp\":\"<>&\u2028\u2029\"}]")
	if e != nil || !bytes.Equal(canonical, want) {
		t.Fatalf("canonical=%s %v", canonical, e)
	}
}

func TestManagerImagePolicyAndProxy(t *testing.T) {
	f := loadManagerFixture(t)
	bundle, e := os.ReadFile("../test-fixtures/provenance/compose-manager-launcher.bundle.json")
	if e != nil {
		t.Fatal(e)
	}
	rootJSON, e := os.ReadFile("../test-fixtures/provenance/trusted-root.json")
	if e != nil {
		t.Fatal(e)
	}
	trusted, e := root.NewTrustedRootFromJSON(rootJSON)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "" {
			t.Error("GitHub token leaked to proxy")
		}
		if strings.Contains(r.URL.Path, "/contents/") {
			if r.URL.Query().Get("ref") != strings.Repeat("12", 20) {
				t.Error(r.URL)
			}
			w.Write([]byte(f.Compose))
		} else {
			json.NewEncoder(w).Encode(map[string]any{"attestations": []any{map[string]any{"bundle": json.RawMessage(bundle)}}})
		}
	}))
	defer server.Close()
	policy := ImageProvenancePolicy{Repository: "nearai/compose-manager", Workflow: ".github/workflows/build.yml"}
	options := ComposeManagerDeploymentImageProvenanceOptions{ProvenanceOptions: ProvenanceOptions{TrustedRoot: trusted, GitHubProxyURL: server.URL + "/proxy", GitHubToken: "never-forward"}, ManagerImagePolicy: ComposeManagerImagePolicy{ImageRepository: "nearaidev/compose-manager-launcher", Build: policy}}
	policies := map[string]ImageProvenancePolicy{"nearaidev/compose-manager-launcher": policy}
	deployment := MeasuredDeployment{ComposeManager: &VerifiedComposeManagerAttestation{Actions: f.Actions}}
	if e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, policies, options); e != nil {
		t.Fatal(e)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
	calls = 0
	e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, nil, options)
	requireCode(t, e, "provenance.deployment_images_invalid")
	if calls != 0 {
		t.Fatal(calls)
	}
	for _, image := range []any{nil, "other/manager@sha256:" + strings.Repeat("aa", 32)} {
		f.Actions[1]["image"] = image
		calls = 0
		e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, policies, options)
		requireCode(t, e, "provenance.compose_manager_deployment_invalid")
		if calls != 0 {
			t.Fatal(calls)
		}
	}
	f.Actions[1]["image"] = "nearaidev/compose-manager-launcher@sha256:" + strings.Repeat("bb", 32)
	e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, policies, options)
	requireCode(t, e, "provenance.verification_failed")
	f.Actions = loadManagerFixture(t).Actions
	deployment.ComposeManager.Actions = f.Actions
	f.Actions[0]["services"] = []string{"missing"}
	e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, policies, options)
	requireCode(t, e, "provenance.deployment_images_invalid")
	f.Actions[0]["services"] = []string{"model"}
	f.Compose += "  unselected:\n    image: ${IGNORED}\n"
	f.Actions[0]["file_sha256"] = hashText([]byte(f.Compose))
	if e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, policies, options); e != nil {
		t.Fatal(e)
	}
	f.Compose += " "
	e = VerifyComposeManagerDeploymentImageProvenance(context.Background(), deployment, policies, options)
	requireCode(t, e, "provenance.compose_file_hash_mismatch")
}

func TestDirectManagerEvidenceOnlyComesFromEnvelope(t *testing.T) {
	f := loadManagerFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		report := map[string]any{"model_name": "test", "request_nonce": nonce, "signing_algo": "ed25519", "signing_address": strings.Repeat("aa", 32), "intel_quote": "bb", "event_log": []any{}, "info": map[string]any{"tcb_info": map[string]any{"app_compose": "{}"}}}
		nested := map[string]any{}
		for k, v := range report {
			nested[k] = v
		}
		nested["compose_manager_attestation"] = ComposeManagerAttestation{Actions: f.Actions, ActionsHash: f.ActionsHash, Nonce: nonce, IntelQuote: "cc", EventLog: json.RawMessage(`[]`)}
		report["all_attestations"] = []any{nested}
		json.NewEncoder(w).Encode(report)
	}))
	defer server.Close()
	client, e := NewDirectAttestationClient(ClientOptions{BaseURL: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	result, e := client.FetchModelAttestations(context.Background(), "test", FetchOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if result.ServingAttestation.ComposeManagerAttestation != nil || result.Attestations[0].ComposeManagerAttestation != nil {
		t.Fatal("nested evidence was promoted")
	}
}

func TestComposeFileSizeBoundPrecedesHashAndParsing(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(itoa(boolInt(chunked)), func(t *testing.T) {
			fixture := loadManagerFixture(t)
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if chunked {
					w.(http.Flusher).Flush()
				} else {
					w.Header().Set("Content-Length", itoa(maxComposeFileBytes+1))
				}
				_, _ = w.Write(bytes.Repeat([]byte("x"), maxComposeFileBytes+1))
			}))
			defer server.Close()
			policy := ImageProvenancePolicy{Repository: "nearai/compose-manager", Workflow: ".github/workflows/build.yml"}
			options := ComposeManagerDeploymentImageProvenanceOptions{ProvenanceOptions: ProvenanceOptions{GitHubProxyURL: server.URL}, ManagerImagePolicy: ComposeManagerImagePolicy{ImageRepository: "nearaidev/compose-manager-launcher", Build: policy}}
			err := VerifyComposeManagerDeploymentImageProvenance(context.Background(), MeasuredDeployment{ComposeManager: &VerifiedComposeManagerAttestation{Actions: fixture.Actions}}, map[string]ImageProvenancePolicy{"nearaidev/compose-manager-launcher": policy}, options)
			requireCode(t, err, "provenance.compose_manager_deployment_invalid")
			if err.(*Error).Details["reason"] != "compose_file_too_large" {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("image proof fetched after oversized file: %d", calls)
			}
		})
	}
}
