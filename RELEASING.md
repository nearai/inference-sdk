# Publishing the SDKs

The npm package is named `@nearai/inference-sdk`. The PyPI and crates.io
packages are named `nearai-inference-sdk`. The npm release candidate is
`0.1.0-rc.1`; Python and Rust remain at `0.1.0`. Python and Rust imports use
`nearai_inference_sdk`. The initial release preparation targets npm only.

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
| npm | `dist/nearai-inference-sdk-0.1.0-rc.1.tgz` |
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

## Publish

Publishing requires an npm account with permission to publish the package,
a PyPI account/API token, and a crates.io account/API token. Configure credentials
through the registry CLI or its supported environment variables; do not commit
credentials. These commands upload public packages and are separate from the
preparation commands above.

From the repository root, publish the reviewed npm release candidate with the
`next` tag so it does not become the default `latest` install:

```sh
npm publish ./dist/nearai-inference-sdk-0.1.0-rc.1.tgz --tag next --access public --registry https://registry.npmjs.org/
```

Install the candidate with `npm install @nearai/inference-sdk@next`, or pin
`@nearai/inference-sdk@0.1.0-rc.1`. Use `0.1.0-rc.2` for a subsequent candidate.
For the formal npm release, change `js/package.json` to `0.1.0`, update this
guide's npm artifact paths, repeat validation, and publish the new archive with
`--tag latest`. Changing a dist-tag does not change a package's version.

Python and Rust publication are separate from this npm candidate:

```sh
uv publish --publish-url https://upload.pypi.org/legacy/ py/dist/nearai_inference_sdk-0.1.0-py3-none-any.whl py/dist/nearai_inference_sdk-0.1.0.tar.gz
(cd rs && cargo publish --locked --registry crates-io)
```

Cargo rebuilds its archive from the committed checkout. npm may request account
authentication or a one-time password. uv accepts `UV_PUBLISH_TOKEN`; Cargo
accepts `CARGO_REGISTRY_TOKEN` or credentials configured by `cargo login`.

The three uploads are independent. If one fails after another succeeds, record
which versions published and retry only the missing uploads after resolving
the failure. Once registry indexing completes, install each published package
in a fresh project and verify its public imports. For this npm-only candidate,
tag the released commit `npm-v0.1.0-rc.1` after publication and installation
checks succeed. Reserve `v0.1.0` for a coordinated formal release of all three
packages.

References: [npm publishing](https://docs.npmjs.com/cli/commands/npm-publish/),
[uv packaging](https://docs.astral.sh/uv/guides/package/), and
[Cargo publishing](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).
