package nearai

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"go.yaml.in/yaml/v3"
)

type ImageProvenancePolicy struct{ Repository, Workflow, Ref, Commit, SignerIdentity, Issuer string }
type VerifiedImageProvenance struct{ Digest, Repository, Workflow, Ref, Commit, CertificateIdentity, Issuer, PredicateType string }

// ProvenanceOptions permits an offline, caller-trusted Sigstore root. Nil selects
// the production root through Sigstore's authenticated TUF update mechanism.
type ProvenanceOptions struct {
	TrustedRoot root.TrustedMaterial
	HTTPClient  *http.Client
	GitHubToken string
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var commitPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func validRepository(s string) bool {
	if !repositoryPattern.MatchString(s) {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}
func FetchImageProvenance(ctx context.Context, repository, digest string, o ProvenanceOptions) ([]json.RawMessage, error) {
	if !validRepository(repository) || !digestPattern.MatchString(digest) {
		return nil, failure("api.invalid_input", nil)
	}
	client := &http.Client{Timeout: time.Minute}
	if o.HTTPClient != nil {
		*client = *o.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := "https://api.github.com/repos/" + repository + "/attestations/" + strings.ToLower(digest) + "?per_page=100"
	target := base
	visited := map[string]bool{}
	var bundles []json.RawMessage
	for {
		if visited[target] {
			return nil, failure("api.invalid_response", nil)
		}
		visited[target] = true
		req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if o.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+o.GitHubToken)
		}
		res, e := client.Do(req)
		if e != nil {
			return nil, &Error{Code: "api.transport_failed", Retryable: true, Cause: e}
		}
		raw, e := readBounded(res.Body, 16<<20)
		res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, &Error{Code: "api.http_status", Details: map[string]any{"status": res.StatusCode}, Retryable: res.StatusCode == 429 || res.StatusCode >= 500}
		}
		if e != nil {
			return nil, e
		}
		var result struct {
			Attestations *[]struct {
				Bundle json.RawMessage `json:"bundle"`
			} `json:"attestations"`
		}
		if e = json.Unmarshal(raw, &result); e != nil || result.Attestations == nil {
			return nil, failure("api.invalid_response", e)
		}
		for _, item := range *result.Attestations {
			if _, e = decodeObject(item.Bundle); e != nil {
				return nil, e
			}
			bundles = append(bundles, item.Bundle)
		}
		next := ""
		for _, link := range strings.Split(strings.Join(res.Header.Values("Link"), ","), ",") {
			parts := strings.Split(link, ";")
			isNext := false
			for _, p := range parts[1:] {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "rel=") {
					for _, rel := range strings.Fields(strings.Trim(strings.TrimPrefix(p, "rel="), `"`)) {
						if rel == "next" {
							isNext = true
						}
					}
				}
			}
			if !isNext {
				continue
			}
			u, e := url.Parse(strings.Trim(strings.TrimSpace(parts[0]), "<>"))
			if e != nil || u.Scheme == "" || u.Host == "" {
				return nil, failure("api.invalid_response", e)
			}
			q, e := url.ParseQuery(u.RawQuery)
			if e != nil {
				return nil, failure("api.invalid_response", e)
			}
			cursor := url.Values{}
			count := 0
			for _, name := range []string{"before", "after"} {
				for _, v := range q[name] {
					count++
					if v == "" {
						return nil, failure("api.invalid_response", nil)
					}
					cursor.Add(name, v)
				}
			}
			if count != 1 || next != "" {
				return nil, failure("api.invalid_response", nil)
			}
			next = base + "&" + cursor.Encode()
		}
		if next == "" {
			return bundles, nil
		}
		target = next
	}
}
func VerifyImageProvenance(ctx context.Context, bundles []json.RawMessage, digest string, policy ImageProvenancePolicy, o ProvenanceOptions) (VerifiedImageProvenance, error) {
	var out VerifiedImageProvenance
	if !digestPattern.MatchString(digest) || !validRepository(policy.Repository) || policy.Workflow == "" || (policy.Commit != "" && !commitPattern.MatchString(policy.Commit)) {
		return out, failure("input.invalid", nil)
	}
	if policy.Issuer == "" {
		policy.Issuer = "https://token.actions.githubusercontent.com"
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	trusted := o.TrustedRoot
	if trusted == nil {
		r, e := root.FetchTrustedRoot()
		if e != nil {
			return out, failure("provenance.verification_failed", e)
		}
		trusted = r
	}
	verifier, e := verify.NewVerifier(trusted, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1), verify.WithSignedCertificateTimestamps(1))
	if e != nil {
		return out, failure("provenance.verification_failed", e)
	}
	hash, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	var last error
	for _, raw := range bundles {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		var b bundle.Bundle
		if e = json.Unmarshal(raw, &b); e != nil {
			last = e
			continue
		}
		content, e := b.VerificationContent()
		if e != nil || content.Certificate() == nil {
			last = e
			continue
		}
		cert := content.Certificate()
		identity := ""
		prefix := "https://github.com/" + policy.Repository + "/" + policy.Workflow + "@"
		for _, uri := range cert.URIs {
			s := uri.String()
			if policy.SignerIdentity != "" {
				if s == policy.SignerIdentity {
					identity = s
					break
				}
			} else if strings.HasPrefix(s, prefix+"refs/") {
				identity = s
				break
			}
		}
		if identity == "" {
			last = fmt.Errorf("untrusted identity")
			continue
		}
		identityPolicy, e := verify.NewShortCertificateIdentity(policy.Issuer, "", identity, "")
		if e != nil {
			last = e
			continue
		}
		result, e := verifier.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", hash), verify.WithCertificateIdentity(identityPolicy)))
		if e != nil {
			last = e
			continue
		}
		verified, e := checkImageStatement(result, cert, identity, strings.ToLower(digest), policy)
		if e != nil {
			last = e
			continue
		}
		return verified, nil
	}
	return out, failure("provenance.verification_failed", last)
}
func certClaim(cert *x509.Certificate, modern, legacy int, legacyPrefix string) (string, error) {
	for _, id := range []int{modern, legacy} {
		oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, id}
		for _, ext := range cert.Extensions {
			if !ext.Id.Equal(oid) {
				continue
			}
			if id == modern {
				var s string
				rest, e := asn1.UnmarshalWithParams(ext.Value, &s, "utf8")
				if e != nil || len(rest) > 0 {
					return "", fmt.Errorf("invalid source extension")
				}
				return s, nil
			}
			return legacyPrefix + string(ext.Value), nil
		}
	}
	return "", fmt.Errorf("missing source extension")
}
func checkImageStatement(result *verify.VerificationResult, cert *x509.Certificate, identity, digest string, p ImageProvenancePolicy) (VerifiedImageProvenance, error) {
	var out VerifiedImageProvenance
	bad := func() (VerifiedImageProvenance, error) { return out, fmt.Errorf("provenance source mismatch") }
	repository, e := certClaim(cert, 12, 5, "https://github.com/")
	if e != nil || repository != "https://github.com/"+p.Repository {
		return bad()
	}
	ref, e := certClaim(cert, 14, 6, "")
	if e != nil || !strings.HasPrefix(ref, "refs/") || (p.Ref != "" && p.Ref != ref) {
		return bad()
	}
	commit, e := certClaim(cert, 13, 3, "")
	if e != nil || !commitPattern.MatchString(commit) {
		return bad()
	}
	if p.Commit != "" && !strings.EqualFold(commit, p.Commit) {
		return bad()
	}
	if p.SignerIdentity == "" && identity != "https://github.com/"+p.Repository+"/"+p.Workflow+"@"+ref {
		return bad()
	}
	statement := result.Statement
	if statement == nil || (statement.Type != "https://in-toto.io/Statement/v1" && statement.Type != "https://in-toto.io/Statement/v0.1") || statement.Predicate == nil {
		return bad()
	}
	predicate := statement.Predicate.AsMap()
	matched := false
	for _, subject := range statement.Subject {
		if strings.EqualFold(subject.Digest["sha256"], strings.TrimPrefix(digest, "sha256:")) {
			matched = true
		}
	}
	if !matched {
		return bad()
	}
	sourceMatches := func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false
		}
		s = strings.TrimPrefix(s, "git+")
		parts := strings.SplitN(s, "@", 2)
		return len(parts) == 2 && strings.TrimSuffix(parts[0], ".git") == repository && parts[1] == ref
	}
	sourceCommit := ""
	switch statement.PredicateType {
	case "https://slsa.dev/provenance/v1":
		definition := object(predicate["buildDefinition"])
		workflow := object(object(definition["externalParameters"])["workflow"])
		repo, _ := workflow["repository"].(string)
		if strings.TrimSuffix(repo, ".git") != repository || workflow["path"] != p.Workflow || workflow["ref"] != ref {
			return bad()
		}
		for _, dep := range objects(definition["resolvedDependencies"]) {
			if sourceMatches(dep["uri"]) {
				sourceCommit, _ = object(dep["digest"])["gitCommit"].(string)
				break
			}
		}
	case "https://slsa.dev/provenance/v0.2":
		source := object(object(predicate["invocation"])["configSource"])
		if !sourceMatches(source["uri"]) || source["entryPoint"] != p.Workflow {
			return bad()
		}
		sourceCommit, _ = object(source["digest"])["sha1"].(string)
	default:
		return bad()
	}
	if !commitPattern.MatchString(sourceCommit) || !strings.EqualFold(sourceCommit, commit) {
		return bad()
	}
	return VerifiedImageProvenance{digest, p.Repository, p.Workflow, ref, strings.ToLower(commit), identity, p.Issuer, statement.PredicateType}, nil
}

// VerifyDeploymentImageProvenance selects all configured repositories from the
// measured app-compose. All matching images must be digest pinned; all policies
// must match a service. No environment expansion or publisher discovery occurs.
func VerifyDeploymentImageProvenance(ctx context.Context, appCompose string, policies map[string]ImageProvenancePolicy, o ProvenanceOptions) error {
	if len(policies) == 0 {
		return failure("provenance.deployment_images_invalid", nil)
	}
	var app struct {
		Compose string `json:"docker_compose_file"`
	}
	if e := json.Unmarshal([]byte(appCompose), &app); e != nil || app.Compose == "" {
		return failure("provenance.deployment_images_invalid", e)
	}
	var compose struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if e := yaml.Unmarshal([]byte(app.Compose), &compose); e != nil || compose.Services == nil {
		return failure("provenance.deployment_images_invalid", e)
	}
	type selection struct {
		digest string
		policy ImageProvenancePolicy
	}
	var selected []selection
	for _, service := range compose.Services {
		if strings.Contains(service.Image, "$") {
			return failure("provenance.deployment_images_invalid", nil)
		}
	}
	for repository, policy := range policies {
		repo := strings.TrimPrefix(repository, "docker.io/")
		if repo == "" {
			return failure("provenance.deployment_images_invalid", nil)
		}
		pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(repo) + `(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@(sha256:[0-9a-fA-F]{64})$`)
		found := false
		for _, service := range compose.Services {
			image := strings.TrimPrefix(service.Image, "docker.io/")
			if image == repo || strings.HasPrefix(image, repo+"@") || strings.HasPrefix(image, repo+":") {
				found = true
				match := pattern.FindStringSubmatch(image)
				if match == nil {
					return failure("provenance.deployment_images_invalid", nil)
				}
				selected = append(selected, selection{strings.ToLower(match[1]), policy})
			}
		}
		if !found {
			return failure("provenance.deployment_images_invalid", nil)
		}
	}
	for _, item := range selected {
		bundles, e := FetchImageProvenance(ctx, item.policy.Repository, item.digest, o)
		if e != nil {
			return failure("provenance.image_request_failed", e)
		}
		if _, e = VerifyImageProvenance(ctx, bundles, item.digest, item.policy, o); e != nil {
			return e
		}
	}
	return nil
}
