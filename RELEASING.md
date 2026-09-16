# Publishing the SDKs

The npm package is named `@nearai/inference-sdk`. The PyPI and crates.io
packages are named `verifiable-ai-sdk`. The prepared release version is `0.1.0`
in all three manifests. Python and Rust imports use `verifiable_ai_sdk`.

## Prepare and validate

Use Node.js 24, pnpm 11.24.0, Python 3.12 with uv, and a current stable Rust
toolchain. Run these commands from the repository root:

```sh
mkdir -p dist
(cd js && pnpm install --frozen-lockfile && pnpm check && pnpm pack --pack-destination ../dist)
(cd py && uv sync --locked && make lint && uv build --no-sources)
(cd py && uv run --with twine twine check dist/verifiable_ai_sdk-0.1.0*)
(cd rs && make check && cargo publish --dry-run --locked --registry crates-io)
```

The Cargo dry run requires a clean package checkout. During preparation only,
`--allow-dirty` permits validation of reviewed, uncommitted changes. Commit the
release changes and rerun the dry run without that flag before publishing.

Release artifacts:

| Registry | Artifact |
| --- | --- |
| npm | `dist/nearai-inference-sdk-0.1.0.tgz` |
| PyPI | `py/dist/verifiable_ai_sdk-0.1.0-py3-none-any.whl` and `py/dist/verifiable_ai_sdk-0.1.0.tar.gz` |
| crates.io | `rs/target/package/verifiable-ai-sdk-0.1.0.crate` |

Inspect archive contents and test installation from the npm tarball and Python
wheel in temporary projects outside the checkout. Check that the npm default
and `/node` entry points import, Python's public exports import, and license
files and type declarations are present. Cargo's dry run compiles the packaged
crate. Do not edit sources between validation and publication.

For a later release, update all three manifest versions and refresh the pnpm,
uv, and Cargo lockfiles as needed. Update the versioned commands here. A
published version cannot be overwritten; verify availability again immediately
before publishing. A missing registry entry does not guarantee permission to
claim the name.

## Publish

Publishing requires an npm account with permission to publish the package,
a PyPI account/API token, and a crates.io account/API token. Configure credentials
through the registry CLI or its supported environment variables; do not commit
credentials. These commands upload public packages and are separate from the
preparation commands above.

From the repository root, publish the reviewed artifacts:

```sh
npm publish ./dist/nearai-inference-sdk-0.1.0.tgz --access public --registry https://registry.npmjs.org/
uv publish --publish-url https://upload.pypi.org/legacy/ py/dist/verifiable_ai_sdk-0.1.0-py3-none-any.whl py/dist/verifiable_ai_sdk-0.1.0.tar.gz
(cd rs && cargo publish --locked --registry crates-io)
```

Cargo rebuilds its archive from the committed checkout. npm may request account
authentication or a one-time password. uv accepts `UV_PUBLISH_TOKEN`; Cargo
accepts `CARGO_REGISTRY_TOKEN` or credentials configured by `cargo login`.

The three uploads are independent. If one fails after another succeeds, record
which versions published and retry only the missing uploads after resolving
the failure. Once registry indexing completes, install each published package
in a fresh project and verify its public imports. Tag the released commit
`v0.1.0` after all three uploads succeed.

References: [npm publishing](https://docs.npmjs.com/cli/commands/npm-publish/),
[uv packaging](https://docs.astral.sh/uv/guides/package/), and
[Cargo publishing](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).
