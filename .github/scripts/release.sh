#!/usr/bin/env bash
# Shared by release jobs. Callers use bash -e -o pipefail.

verify_release_tag() {
  local commit
  # The commits API resolves both lightweight and annotated tags.
  commit=$(gh api "repos/$GH_REPO/commits/refs%2Ftags%2F$RELEASE_TAG" --jq .sha) || return $?
  if [ "$commit" != "$GITHUB_SHA" ]; then
    printf 'Tag %s no longer points to the workflow commit.\n' "$RELEASE_TAG" >&2
    return 1
  fi
}

registry_version_exists() {
  local status
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --user-agent 'nearai-inference-sdk-release (https://github.com/nearai/inference-sdk)' \
    "$1") || return $?
  case "$status" in
    200) printf 'true\n' ;;
    404) printf 'false\n' ;;
    *) printf 'Registry version lookup failed with HTTP %s.\n' "$status" >&2; return 1 ;;
  esac
}

require_verified_retry() {
  local job="$1" upload_step="$2" attempt uploaded
  # Re-runs retain the original run ID, commit, and inputs. An existing draft
  # or a larger attempt number alone does not prove that we uploaded anything.
  for ((attempt = GITHUB_RUN_ATTEMPT - 1; attempt >= 1; attempt--)); do
    uploaded=$(gh api --paginate \
      "repos/$GH_REPO/actions/runs/$GITHUB_RUN_ID/attempts/$attempt/jobs?per_page=100" \
      --jq ".jobs[] | select(.name == \"$job\") | .steps[] | select(.name == \"$upload_step\" and .conclusion == \"success\") | .number") || return $?
    if [ -n "$uploaded" ]; then
      printf 'Version already uploaded successfully by this workflow run (attempt %s).\n' "$attempt"
      return 0
    fi
  done
  printf 'Version already exists without a successful upload in this workflow run. Reconcile it manually; do not reuse the version.\n' >&2
  return 1
}
