package nearai

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const maxComposeFileBytes = 8 * 1024 * 1024

// ComposeManagerImagePolicy applies only to the latest manager-start action.
type ComposeManagerImagePolicy struct {
	ImageRepository string
	Build           ImageProvenancePolicy
}
type ComposeManagerDeploymentImageProvenanceOptions struct {
	ProvenanceOptions
	ComposeRepository         string
	ComposeFile               string
	ComposeManagerImagePolicy ComposeManagerImagePolicy
}

// VerifyComposeManagerDeploymentImageProvenance authenticates recorded intent.
// Call it from a deployment verifier after quote validation; it does not itself
// verify the quote or assert which containers are currently running.
func VerifyComposeManagerDeploymentImageProvenance(ctx context.Context, deployment MeasuredDeployment, policies map[string]ImageProvenancePolicy, o ComposeManagerDeploymentImageProvenanceOptions) error {
	invalid := func(reason string) error {
		return detail("provenance.compose_manager_deployment_invalid", "reason", reason)
	}
	if len(policies) == 0 {
		return detail("provenance.deployment_images_invalid", "reason", "empty_policy")
	}
	if deployment.ComposeManager == nil {
		return invalid("attestation_missing")
	}
	var action, started ComposeManagerAction
	for i := len(deployment.ComposeManager.Actions) - 1; i >= 0; i-- {
		a := deployment.ComposeManager.Actions[i]
		if action == nil && actionString(a, "action") == "compose_up" && (o.ComposeFile == "" || actionString(a, "file") == o.ComposeFile) {
			action = a
		}
		if started == nil && actionString(a, "action") == "compose_manager_started" {
			started = a
		}
	}
	if action == nil {
		return invalid("compose_up_missing")
	}
	image, ok := started["image"].(string)
	if !ok {
		return invalid("manager_image_missing")
	}
	repo := strings.TrimPrefix(o.ComposeManagerImagePolicy.ImageRepository, "docker.io/")
	normalized := strings.TrimPrefix(image, "docker.io/")
	if repo == "" || (!strings.HasPrefix(normalized, repo+"@") && !strings.HasPrefix(normalized, repo+":")) {
		return invalid("manager_image_mismatch")
	}
	managerPin := pinnedImageSuffixPattern.FindStringSubmatch(strings.TrimPrefix(normalized, repo))
	if managerPin == nil {
		return failure("provenance.deployment_images_invalid", nil)
	}
	repository := o.ComposeRepository
	if repository == "" {
		repository = "nearai/cvm-compose-files"
	}
	commit, file, digest := actionString(action, "commit"), actionString(action, "file"), actionString(action, "file_sha256")
	if !validRepository(repository) || !commitPattern.MatchString(commit) || !digestPattern.MatchString("sha256:"+digest) {
		return invalid("invalid_file_reference")
	}
	parts := strings.Split(file, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return invalid("invalid_file_reference")
		}
		parts[i] = url.PathEscape(part)
	}
	base, err := provenanceAPIBase(o.GitHubProxyURL)
	if err != nil {
		return err
	}
	target := base + "/repos/" + repository + "/contents/" + strings.Join(parts, "/") + "?ref=" + url.QueryEscape(commit)
	request, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github.raw+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if o.GitHubToken != "" && o.GitHubProxyURL == "" {
		request.Header.Set("Authorization", "Bearer "+o.GitHubToken)
	}
	client := &http.Client{Timeout: time.Minute}
	if o.HTTPClient != nil {
		*client = *o.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return &Error{Code: "provenance.compose_file_request_failed", Retryable: true, Cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &Error{Code: "provenance.compose_file_request_failed", Details: map[string]any{"status": response.StatusCode}, Retryable: response.StatusCode == 429 || response.StatusCode >= 500}
	}
	if response.ContentLength > maxComposeFileBytes {
		return invalid("compose_file_too_large")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxComposeFileBytes+1))
	if err != nil {
		return &Error{Code: "provenance.compose_file_request_failed", Retryable: true, Cause: err}
	}
	if len(body) > maxComposeFileBytes {
		return invalid("compose_file_too_large")
	}
	if !strings.EqualFold(hashText(body), digest) {
		return failure("provenance.compose_file_hash_mismatch", nil)
	}
	if !utf8.Valid(body) {
		return detail("provenance.deployment_images_invalid", "reason", "invalid_docker_compose")
	}
	services, _ := action["services"].([]string)
	if err = verifyComposeImages(ctx, string(body), policies, o.ProvenanceOptions, services); err != nil {
		return err
	}
	return verifyRequiredImage(ctx, strings.ToLower(managerPin[1]), o.ComposeManagerImagePolicy.Build, o.ProvenanceOptions)
}
