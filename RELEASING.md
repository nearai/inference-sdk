# Releasing

The npm package is named `@nearai/inference-sdk`; the PyPI and crates.io
packages are named `nearai-inference-sdk`. The current npm release candidate is
`0.1.0-rc.2`; Python and Rust remain at `0.1.0`. Python and Rust imports use
`nearai_inference_sdk`.

## Prepare and validate

Use Node.js 24, pnpm 11.24.0, Python 3.12 with uv, and a current stable Rust
toolchain. Run these commands from the repository root:

```sh
mkdir -p dist
(cd js && pnpm install --frozen-lockfile && pnpm check && pnpm pack --pack-destination ../dist)
(cd py && uv sync --locked && make lint && uv build --no-sources)
(cd py && uv run --with twine twine check dist/nearai_inference_sdk-0.1.0*)
(cd rs && make check && cargo publish --dry-run --locked --registry crates-io)
```

The Cargo dry run requires a clean package checkout. During preparation only,
`--allow-dirty` permits validation of reviewed, uncommitted changes. Commit the
release changes and rerun the dry run without that flag before publishing.

Release artifacts:

| Registry | Artifact |
| --- | --- |
| npm | `dist/nearai-inference-sdk-0.1.0-rc.2.tgz` |
| PyPI | `py/dist/nearai_inference_sdk-0.1.0-py3-none-any.whl` and `py/dist/nearai_inference_sdk-0.1.0.tar.gz` |
| crates.io | `rs/target/package/nearai-inference-sdk-0.1.0.crate` |

Inspect archive contents and test installation from the npm tarball and Python
wheel in temporary projects outside the checkout. Check that the npm default
and `/node` entry points import, Python's public exports import, and license
files and type declarations are present. Cargo's dry run compiles the packaged
crate. Do not edit sources between validation and publication.

For a later release, update the relevant manifest versions and refresh the
corresponding lockfiles as needed. Update the versioned commands here. A
published version cannot be overwritten; verify availability again immediately
before publishing. A missing registry entry does not guarantee permission to
claim the name.

## npm release candidates

Publish a reviewed npm candidate manually with the `next` tag so it does not
become the default `latest` install:

```sh
npm publish ./dist/nearai-inference-sdk-0.1.0-rc.2.tgz --tag next --access public --registry https://registry.npmjs.org/
```

Install the candidate with `npm install @nearai/inference-sdk@next`, or pin
`@nearai/inference-sdk@0.1.0-rc.2`. Use `0.1.0-rc.3` for a later candidate.
Tag a published candidate with the separate `npm-vX.Y.Z-rc.N` convention. These
tags do not trigger the coordinated release workflow. Manual npm publishing
uses an account authorized for the package and may require login or an OTP.

## Initial Python and Rust publication

Python and Rust publication can be performed manually while bootstrapping their
registry projects:

```sh
uv publish --publish-url https://upload.pypi.org/legacy/ py/dist/nearai_inference_sdk-0.1.0-py3-none-any.whl py/dist/nearai_inference_sdk-0.1.0.tar.gz
(cd rs && cargo publish --locked --registry crates-io)
```

PyPI supports a pending trusted publisher before its initial upload. npm and
crates.io require an existing package before their trusted publisher can be
configured, so publish the initial version manually and use a later version for
the first fully automated coordinated release. For manual bootstrap, `uv`
accepts `UV_PUBLISH_TOKEN`, while Cargo accepts `CARGO_REGISTRY_TOKEN` or
credentials from `cargo login`; do not commit those credentials.

## Automated coordinated stable releases

Pushing a stable `vX.Y.Z` tag starts the **Publish packages** workflow. It
checks that the tag is reachable from the default branch, all three manifest
versions equal `X.Y.Z`, and the full CI workflow passes. It then creates a
draft GitHub Release, publishes all three packages, and makes the release public
only after every publish job succeeds.

Create a GitHub Actions environment named `release`; restrict it to protected
`v*` tags and add required reviewers only if releases should require manual
approval. Configure each registry to trust this publisher:

| Setting | Value |
| --- | --- |
| GitHub organization | `nearai` |
| Repository | `inference-sdk` |
| Workflow file | `release.yml` |
| Environment | `release` |

Configure npm for `@nearai/inference-sdk` and allow direct `npm publish`, then
configure PyPI and crates.io for `nearai-inference-sdk`. The workflow uses
short-lived OIDC credentials; no long-lived registry token is needed.

For a coordinated stable release:

1. In a release PR, set `X.Y.Z` in `js/package.json`,
   `py/pyproject.toml`, and `rs/Cargo.toml`, then refresh the relevant lockfiles.
2. Merge the release PR into the default branch.
3. Create and push the matching tag from that merged commit:

   ```sh
   git switch main
   git pull --ff-only
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

Registry uploads are independent. If one job fails after another registry has
accepted its version, keep the tag and draft release, confirm which versions
exist, then rerun only the missing publish job. Published package versions are
immutable; never create a second release tag for the same version.

See the registry setup guides for [npm](https://docs.npmjs.com/trusted-publishers/),
[PyPI](https://docs.pypi.org/trusted-publishers/using-a-publisher/), and
[crates.io](https://crates.io/docs/trusted-publishing/).
