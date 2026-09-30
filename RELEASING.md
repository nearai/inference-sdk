# Releasing

Each SDK is released independently through the **Publish package** GitHub
Actions workflow. Choose one language and its version. Pushing a tag does not
start a release.

| Language input | Registry package | Version source | Release tag |
| --- | --- | --- | --- |
| `javascript` | npm: `@nearai/inference-sdk` | `js/package.json` | `javascript-v<version>` |
| `python` | PyPI: `nearai-inference-sdk` | `py/pyproject.toml` | `python-v<version>` |
| `rust` | crates.io: `nearai-inference-sdk` | `rs/Cargo.toml` | `rust-v<version>` |

The input version must exactly match the selected manifest. The workflow does
not bump versions or require the other SDKs to use the same version.

## Prepare a release

1. Update the selected package's manifest and its lockfile as needed in a PR.
2. Run its checks and inspect the package contents using the commands below.
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

In GitHub, open **Actions → Publish package → Run workflow**. Select `main`,
choose `javascript`, `python`, or `rust`, and enter the version without a `v`
prefix. For example, after merging an npm version bump to `0.1.0`:

```sh
gh workflow run release.yml --repo nearai/inference-sdk --ref main \
  -f language=javascript -f version=0.1.0
```

The workflow:

1. Requires the default branch and checks the selected manifest's version.
2. Runs CI and live E2E against both STG and PRD for the selected language.
   A failure blocks tag creation and publication. Ordinary PR and push CI still
   checks all three languages without contacting the service.
3. Creates the package-specific tag at the run's commit and a draft GitHub
   Release. An existing tag must point to that same commit.
4. Rechecks the remote tag and publishes only the selected package, using the
   `release` environment. Published versions are not automatically skipped.
5. Rechecks the remote tag before making its GitHub Release public.

JavaScript and Rust accept `X.Y.Z` or prerelease versions such as `X.Y.Z-rc.1`.
Python uses normalized public PEP 440 versions, such as `1.0.0` or `1.0.0rc1`.
Prereleases are marked as such on GitHub. npm prereleases use the `next`
dist-tag, while stable versions use `latest`; candidates do not replace the
default stable install.

## Registry setup

Configure the `NEARAI_STG_API_KEY` and `NEARAI_PRD_API_KEY` repository secrets
for the live release checks. See [Live E2E configuration](e2e/README.md#configuration).

Create a GitHub Actions environment named `release`, restrict deployments to
the default branch, and optionally add required reviewers. Add a tag ruleset for
`javascript-v*`, `python-v*`, and `rust-v*` that restricts updates and deletions, without
blocking creation by the release workflow. Draft-release tags are not immutable;
these rules prevent changes between the workflow's tag check and publication.
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
selected registry needs to be configured for that release.

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
retrying. Keep the package tag and draft release. Rerunning failed jobs in the
original workflow run keeps the same source commit and inputs even if `main`
has advanced.

- If the upload did not reach the registry, fix the cause and rerun failed jobs.
- If the package job succeeded and only GitHub Release publication failed,
  rerun failed jobs to finish the release without repeating the upload.
- If the upload was accepted but the package job failed, or a Python upload is
  partial, check the registry artifacts against the original build and finish
  recovery manually. The workflow does not skip existing versions or repair
  partial uploads.

npm uploads also check that the candidate will not move `latest` or `next`
backward. A version comparison or registry lookup failure stops publication.

Published versions cannot be overwritten. If the fix changes package contents,
prepare a new version instead of moving its tag. After publication, install the
released package in a fresh project and verify its public imports.
