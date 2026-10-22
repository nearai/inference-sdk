# Releasing

Use the **Publish packages** GitHub Actions workflow to release one or more
SDKs from the same commit. Check the languages to publish and enter one shared
version. Pushing a tag does not start the workflow; for Go, the tag itself makes
the module installable.

| Language checkbox | Registry package | Version source |
| --- | --- | --- |
| `javascript` | npm: `@nearai/inference-sdk` | `js/package.json` |
| `python` | PyPI: `nearai-inference-sdk` | `py/pyproject.toml` |
| `rust` | crates.io: `nearai-inference-sdk` | `rs/Cargo.toml` |
| `go` | Go proxy: `github.com/nearai/inference-sdk/go` | Workflow input |

Each version has one GitHub Release tagged `v<version>`, with the selected SDKs,
their package versions, and the source commit in its notes. Go also uses
`go/v<version>` for its module, without a separate GitHub Release.

Enter SemVer without `v`, such as `0.2.0` or `0.2.0-rc.1`, including when only
Python is selected. JavaScript, Rust, and Go use that version directly; Python
converts `0.2.0-rc.1` to `0.2.0rc1`. Python also maps `-alpha.N` to `aN` and
`-beta.N` to `bN`; other SemVer prerelease labels require Python to be unchecked.

Each selected manifest must already match its resolved package version. Update
versions and lockfiles in a preparation PR; the workflow validates them without
editing them. Go has no package version field. Go major versions >=2 require a
new module path first. Unchecked SDKs are not released and may have other versions.

## Prepare a release

1. Update each selected package's manifest and its lockfile as needed in a PR.
   Go has no version field; prepare code and documentation changes as needed.
2. Run their checks and inspect the package contents using the commands below.
3. Merge the release preparation into the default branch (`main`).

Use Node.js 24 and pnpm 11.24.0 for JavaScript, Python 3.12 with uv for Python,
and a current stable Rust toolchain for Rust. Run the commands for the SDK being
released from the repository root.

### JavaScript

```sh
cd js
pnpm install --frozen-lockfile
pnpm check
pnpm pack
```

Install the tarball in a temporary project and check the default and `/node`
imports, type declarations, and license files.

### Python

```sh
cd py
uv sync --locked
make lint
uv build --no-sources
uv run --with twine twine check dist/*
```

Install the wheel in a temporary project and check its public imports and
`py.typed`. Only the newly built version should be uploaded.

### Rust

```sh
cd rs
make check
cargo publish --dry-run --locked --registry crates-io
```

The Cargo dry run requires a clean package checkout and compiles the packaged
crate. During preparation, `--allow-dirty` permits validation of uncommitted
changes. Commit those changes and repeat without that flag before publication.

## Run the workflow

In GitHub, open **Actions → Publish packages → Run workflow**. Select `main`,
check at least one of `javascript`, `python`, `rust`, and `go`, and enter the shared
version. All checkboxes default to unchecked. For example, after merging version
bumps to `0.2.0-rc.1` for JavaScript/Rust and `0.2.0rc1` for Python:

```sh
gh workflow run release.yml --repo nearai/inference-sdk --ref main \
  -F javascript=true -F python=true -F rust=true -F go=true \
  -f version=0.2.0-rc.1
```

To publish only Python `0.2.0rc1`:

```sh
gh workflow run release.yml --repo nearai/inference-sdk --ref main \
  -F python=true -f version=0.2.0-rc.1
```

The workflow:

1. Requires the default branch, validates every selected package version, and
   shows the resolved versions and tags in the run summary.
2. Runs CI and live E2E against both STG and PRD for each selected language.
   All selected checks must pass before any tag creation or publication.
   Ordinary PR and push CI still checks all four languages without contacting
   the service.
3. Creates the shared `v<version>` tag at the run's commit and one draft GitHub
   Release. Existing tags must point to that same commit, and an existing draft
   must match the selected SDKs and their package versions.
4. Rechecks remote tags and publishes the selected packages in parallel, using
   the `release` environment. For Go, this creates `go/v<version>` and verifies
   a fresh public-proxy consumer after environment approval.
   Published versions are not automatically skipped.
5. Makes the combined GitHub Release public only after every selected package
   succeeds and the tags and release plan still match. Otherwise it stays a draft.
   The summary lists each package's result.

Prereleases are marked as such on GitHub. npm prereleases use the `next`
dist-tag, while stable versions use `latest`; candidates do not replace the
default stable install.

Release workflow runs are serialized to prevent overlapping batches from
publishing the same package concurrently.

## Registry setup

Configure the `NEARAI_STG_API_KEY` and `NEARAI_PRD_API_KEY` repository secrets
for the live release checks. See [Live E2E configuration](e2e/README.md#configuration).

Create a GitHub Actions environment named `release`, restrict deployments to
the default branch, and optionally add required reviewers. Add tag rulesets for
`v*` and `go/v*` that allow the workflow to create tags and block later updates
or deletions.
Configure trusted publishing for each registry you intend to use:

| Setting | Value |
| --- | --- |
| GitHub organization | `nearai` |
| Repository | `inference-sdk` |
| Workflow file | `release.yml` |
| Environment | `release` |

For npm, configure `@nearai/inference-sdk` and allow direct `npm publish`.
For PyPI and crates.io, configure `nearai-inference-sdk`. The workflow uses
short-lived OIDC credentials rather than long-lived registry tokens. Only the
selected registries need to be configured for that release.

PyPI supports a pending trusted publisher before the first upload. npm and
crates.io require an existing package to configure trusted publishing; if a
package has not been created yet, publish its initial version manually using an
authorized account. Configure credentials through the registry CLI or its
supported environment variables, never in committed files.

Registry setup guides: [npm](https://docs.npmjs.com/trusted-publishers/),
[PyPI](https://docs.pypi.org/trusted-publishers/adding-a-publisher/), and
[crates.io](https://crates.io/docs/trusted-publishing/).

## Retry a failed release

Check the failed job and whether the registry accepted the upload before
retrying. Keep the tags and draft release. Rerunning failed jobs in the
original workflow run keeps the same source commit and inputs even if `main`
has advanced.

A batch can partially succeed because the registries publish independently;
keeping the GitHub Release in draft does not hide or roll back uploaded packages.
Use **Re-run failed jobs** in the original run so successful package uploads are
not repeated. This also reruns the finalization job after the remaining packages
succeed. The source commit and SDK selection are fixed for that version; a new
dispatch with a different plan is rejected. Avoid **Re-run all jobs** or starting
a fresh batch with the same published versions.

- If the upload did not reach the registry, fix the cause and rerun failed jobs.
- If the package job succeeded and only GitHub Release publication failed,
  rerun failed jobs to finish the release without repeating the upload. If the
  release was already made public, finalization leaves it unchanged.
- If the upload was accepted but the package job failed, or a Python upload is
  partial, check the registry artifacts against the original build and finish
  recovery manually. The workflow does not skip existing versions or repair
  partial uploads.

npm uploads also check that the candidate will not move `latest` or `next`
backward. A version comparison or registry lookup failure stops publication.

Published versions cannot be overwritten. If the fix changes package contents,
prepare a new version instead of moving its tag. After publication, install the
released package in a fresh project and verify its public imports.

## Go module

Check `go` in **Publish packages**, run it from `main`, and enter the version
without `v`. The module has no manifest version to bump. Update documentation or
code in a reviewed PR as needed, then merge it before starting the workflow.

Before publishing, the workflow runs Go formatting, vet, race tests, Linux/macOS
checks, CGO-disabled builds, examples, embedded WASM reproduction, and staging
and production live E2E. The `release` environment gates tag creation, because
creating `go/vX.Y.Z` publishes the Go module immediately.

The workflow creates the module tag at its validated commit and checks
public-proxy availability and a fresh CGO-disabled consumer.
It confirms the proxy source commit, initializes the public client, and exercises
the packaged verifier before the combined GitHub Release can be published.

If post-tag verification fails, the module tag is already public; leave it
immutable. Rerun the failed jobs to retry proxy verification against the same
commit. Code changes require a new version.

No registry token or native-library upload is needed. Consumers install with:

```sh
go get github.com/nearai/inference-sdk/go@v0.1.0
```

Package documentation is indexed by pkg.go.dev from the public Go module proxy.
