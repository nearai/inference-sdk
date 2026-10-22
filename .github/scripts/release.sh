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

create_release_tag() {
  if ! git show-ref --verify --quiet "refs/tags/$RELEASE_TAG"; then
    gh api --method POST "repos/$GH_REPO/git/refs" \
      -f "ref=refs/tags/$RELEASE_TAG" -f "sha=$GITHUB_SHA" >/dev/null || return $?
  fi
  verify_release_tag
}

release_plan_marker() {
  local digest
  # Keep the source commit and selected packages fixed when reusing a draft.
  digest=$(jq -cS --arg commit "$GITHUB_SHA" '{commit: $commit, packages: .}' \
    <<< "$RELEASE_PACKAGES" | sha256sum | cut -d ' ' -f 1) || return $?
  printf '<!-- release-plan: %s -->\n' "$digest"
}

verify_release_plan() {
  local marker
  marker=$(release_plan_marker) || return $?
  if ! jq -r .body <<< "$1" | grep -Fx -- "$marker" >/dev/null; then
    printf 'Release %s has a different source commit or SDK selection.\n' "$RELEASE_TAG" >&2
    return 1
  fi
}

create_github_release() {
  local release notes="$RUNNER_TEMP/release-notes.md"
  create_release_tag || return $?
  if release=$(gh release view "$RELEASE_TAG" --json body,isDraft 2>/dev/null); then
    verify_release_plan "$release" || return $?
    if [ "$(jq -r .isDraft <<< "$release")" != true ]; then
      printf 'GitHub Release %s is already published.\n' "$RELEASE_TAG" >&2
      return 1
    fi
    return 0
  fi

  {
    printf '## SDK versions\n\n| SDK | Package version |\n| --- | --- |\n'
    jq -r 'to_entries[] | "| \(.key) | `\(.value.version)` |"' <<< "$RELEASE_PACKAGES"
    printf '\nSource: [%s](https://github.com/%s/commit/%s)\n\n' \
      "$GITHUB_SHA" "$GH_REPO" "$GITHUB_SHA"
    release_plan_marker
  } > "$notes"
  gh release create "$RELEASE_TAG" --draft --generate-notes --notes-file "$notes" \
    --title "$RELEASE_TAG" --verify-tag --prerelease="$PRERELEASE"
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
  local language result tag release complete=true
  printf '| SDK | Package publication |\n| --- | --- |\n' >> "$GITHUB_STEP_SUMMARY"
  for language in javascript python rust go; do
    tag=$(jq -r --arg language "$language" '.[$language].tag // empty' <<< "$RELEASE_PACKAGES") || return $?
    [ -n "$tag" ] || continue
    result=$(jq -r --arg language "$language" '.[$language]' <<< "$PUBLISH_RESULTS") || return $?
    printf '| %s | %s |\n' "$language" "$result" >> "$GITHUB_STEP_SUMMARY"
    if [ "$result" != success ]; then
      complete=false
    fi
  done
  if [ "$complete" != true ]; then
    printf '\nRelease %s remains a draft until all selected packages succeed.\n' \
      "$RELEASE_TAG" >> "$GITHUB_STEP_SUMMARY"
    return 0
  fi

  verify_release_tag || return $?
  tag=$(jq -r '.go.tag // empty' <<< "$RELEASE_PACKAGES") || return $?
  if [ -n "$tag" ]; then
    RELEASE_TAG="$tag" verify_release_tag || return $?
  fi
  release=$(gh release view "$RELEASE_TAG" --json body,isDraft) || return $?
  verify_release_plan "$release" || return $?
  if [ "$(jq -r .isDraft <<< "$release")" = true ]; then
    gh release edit "$RELEASE_TAG" --draft=false || return $?
  fi
  printf '\nRelease %s is published.\n' "$RELEASE_TAG" >> "$GITHUB_STEP_SUMMARY"
}
