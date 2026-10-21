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

verify_npm_channel() {
  local status current_version
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --user-agent 'nearai-inference-sdk-release (https://github.com/nearai/inference-sdk)' \
    "https://registry.npmjs.org/@nearai%2finference-sdk/$NPM_TAG") || return $?
  case "$status" in
    200) ;;
    404) return 0 ;;
    *) printf 'npm channel lookup failed with HTTP %s.\n' "$status" >&2; return 1 ;;
  esac

  current_version=$(npm view "@nearai/inference-sdk@$NPM_TAG" version \
    --registry=https://registry.npmjs.org) || return $?
  if [ -z "$current_version" ]; then
    printf 'Could not read the current npm %s version.\n' "$NPM_TAG" >&2
    return 1
  fi
  # Use SemVer ordering, including numeric prerelease identifiers, for retries
  # as well as fresh releases. A delayed retry must not roll back latest/next.
  if ! pnpm dlx semver@7.8.5 --include-prerelease \
    --range ">=$current_version" "$RELEASE_VERSION" >/dev/null; then
    printf 'Cannot confirm npm %s is at least %s (%s); refusing publication.\n' \
      "$RELEASE_VERSION" "$current_version" "$NPM_TAG" >&2
    return 1
  fi
}

publish_github_release() {
  local draft
  # Called in a conditional below, so propagate failures explicitly.
  verify_release_tag || return $?
  draft=$(gh release view "$RELEASE_TAG" --json isDraft --jq .isDraft) || return $?
  if [ "$draft" = false ]; then
    return 0
  fi
  if [ "$1" = go ]; then
    gh release edit "$RELEASE_TAG" --draft=false --latest=false
  else
    gh release edit "$RELEASE_TAG" --draft=false
  fi
}

publish_github_releases() {
  local language result tag failed=0
  printf '| SDK | Package publication | GitHub Release |\n| --- | --- | --- |\n' >> "$GITHUB_STEP_SUMMARY"
  for language in javascript python rust go; do
    tag=$(jq -r --arg language "$language" '.[$language].tag // empty' <<< "$RELEASE_PACKAGES") || return $?
    [ -n "$tag" ] || continue
    result=$(jq -r --arg language "$language" '.[$language]' <<< "$PUBLISH_RESULTS") || return $?
    if [ "$result" != success ]; then
      printf '| %s | %s | skipped |\n' "$language" "$result" >> "$GITHUB_STEP_SUMMARY"
      continue
    fi
    # Already-public releases are left unchanged when rerunning failed jobs.
    # Complete every successful package even if another finalization fails.
    if RELEASE_TAG="$tag" publish_github_release "$language"; then
      printf '| %s | success | published |\n' "$language" >> "$GITHUB_STEP_SUMMARY"
    else
      printf '| %s | success | failed |\n' "$language" >> "$GITHUB_STEP_SUMMARY"
      failed=1
    fi
  done
  return "$failed"
}
