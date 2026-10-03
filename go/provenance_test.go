package nearai

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestSharedSignedProvenanceFixtures(t *testing.T) {
	raw, e := os.ReadFile("../test-fixtures/provenance/trusted-root.json")
	if e != nil {
		t.Fatal(e)
	}
	trusted, e := root.NewTrustedRootFromJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	opts := ProvenanceOptions{TrustedRoot: trusted}
	for _, tt := range []struct {
		file, digest string
		policy       ImageProvenancePolicy
	}{
		{"compose-manager-launcher.bundle.json", "sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56", ImageProvenancePolicy{Repository: "nearai/compose-manager", Workflow: ".github/workflows/build.yml"}},
		{"reusable-workflow.bundle.json", "sha256:49a3aa6075e0f49f82843e74b5baa614ad2a588e6675612bf108a0a008c5ac25", ImageProvenancePolicy{Repository: "malancas/attest-demo", Workflow: ".github/workflows/shared.yml", Ref: "refs/heads/main", Commit: "95baf27389e83e6a5c48f42e190d48d7abcea19e", SignerIdentity: "https://github.com/github/artifact-attestations-workflows/.github/workflows/attest.yml@09b495c3f12c7881b3cc17209a327792065c1a1d"}},
	} {
		t.Run(tt.file, func(t *testing.T) {
			b, e := os.ReadFile("../test-fixtures/provenance/" + tt.file)
			if e != nil {
				t.Fatal(e)
			}
			verified, e := VerifyImageProvenance(context.Background(), []json.RawMessage{b}, tt.digest, tt.policy, opts)
			if e != nil {
				var sdk *Error
				if x, ok := e.(*Error); ok {
					sdk = x
				}
				t.Fatalf("%v cause=%v", e, sdk.Cause)
			}
			if verified.Repository != tt.policy.Repository {
				t.Fatal(verified)
			}
			bad := tt.policy
			bad.Repository = "attacker/repo"
			if _, e = VerifyImageProvenance(context.Background(), []json.RawMessage{b}, tt.digest, bad, opts); e == nil {
				t.Fatal("wrong source accepted")
			}
			bad = tt.policy
			bad.Commit = "0000000000000000000000000000000000000000"
			if _, e = VerifyImageProvenance(context.Background(), []json.RawMessage{b}, tt.digest, bad, opts); e == nil {
				t.Fatal("wrong commit accepted")
			}
			if _, e = VerifyImageProvenance(context.Background(), []json.RawMessage{b}, "sha256:0000000000000000000000000000000000000000000000000000000000000000", tt.policy, opts); e == nil {
				t.Fatal("wrong digest accepted")
			}
		})
	}
}
func TestDeploymentSelectionRejectsBeforeFetching(t *testing.T) {
	p := map[string]ImageProvenancePolicy{"example/image": {Repository: "example/repo", Workflow: ".github/workflows/build.yml"}}
	for _, compose := range []string{"services: {}", "services:\n  app:\n    image: example/image:latest", "services:\n  app:\n    image: ${IMAGE}"} {
		app, _ := json.Marshal(map[string]string{"docker_compose_file": compose})
		e := VerifyDeploymentImageProvenance(context.Background(), string(app), p, ProvenanceOptions{})
		requireCode(t, e, "provenance.deployment_images_invalid")
	}
}
