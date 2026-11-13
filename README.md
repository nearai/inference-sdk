<p align="center">
  <img src="./.github/assets/readme-banner.svg" alt="NEAR AI Inference SDK — Private inference. Verifiable responses." width="100%">
</p>

<p align="center">
  Attestation, response signatures, and optional encryption for NEAR AI Cloud.<br>
  Use Chat Completions, Responses, Messages, or System One from TypeScript, Python, Rust, and Go.
</p>

<p align="center">
  <a href="https://github.com/nearai/inference-sdk/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/nearai/inference-sdk/ci.yml?branch=main&amp;style=flat-square&amp;label=CI" alt="CI status"></a>
  <a href="https://www.npmjs.com/package/@nearai/inference-sdk"><img src="https://img.shields.io/npm/v/@nearai/inference-sdk?style=flat-square&amp;color=0091fd" alt="npm version"></a>
  <a href="https://pypi.org/project/nearai-inference-sdk/"><img src="https://img.shields.io/pypi/v/nearai-inference-sdk?style=flat-square&amp;color=0091fd" alt="PyPI version"></a>
  <a href="https://crates.io/crates/nearai-inference-sdk"><img src="https://img.shields.io/crates/v/nearai-inference-sdk?style=flat-square&amp;color=0091fd" alt="crates.io version"></a>
  <a href="https://pkg.go.dev/github.com/nearai/inference-sdk/go"><img src="https://img.shields.io/badge/Go-reference-0091fd?style=flat-square" alt="Go reference"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-0091fd?style=flat-square" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#sdks-and-installation">Install</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="https://github.com/nearai/inference-sdk/releases">Releases</a>
</p>

## SDKs and installation

| Language | Install | Get started |
| --- | --- | --- |
| **TypeScript / JavaScript** | `npm install @nearai/inference-sdk` | [Node.js & browser guide](./js/README.md) |
| **Python** | `pip install nearai-inference-sdk` | [Python guide](./py/README.md) |
| **Rust** | `cargo add nearai-inference-sdk` | [Rust guide](./rs/README.md) |
| **Go** | `go get github.com/nearai/inference-sdk/go` | [Go guide](./go/README.md) |

See each language guide for runtime requirements and configuration.

## How verification works

1. **Check the deployment.** The Gateway client verifies Gateway evidence and
   model evidence when supported. Required verification failures stop the request.
2. **Send the request.** Enable E2EE to encrypt Chat content for the model, or OHTTP to
   encrypt supported requests to the Gateway.
3. **Verify the response.** Use the SDK's response verification before using the
   answer. For streaming, consume the entire stream first.

A `provider_tee` receipt is signed by an attested model signer. A `gateway`
receipt is signed by an attested Gateway signer.

## Documentation

| SDK | Verification guide | API reference |
| --- | --- | --- |
| **TypeScript / JavaScript** | [Encryption, streaming & policies](./js/docs/verification-guide.md) | [Types & methods](./js/docs/api-reference.md) |
| **Python** | [Encryption, streaming & policies](./py/docs/verification-guide.md) | [Types & methods](./py/docs/api-reference.md) |
| **Rust** | [Encryption, streaming & policies](./rs/docs/verification-guide.md) | [Types & methods](./rs/docs/api-reference.md) |
| **Go** | [Encryption, streaming & policies](./go/docs/verification-guide.md) | [Types & methods](./go/docs/api-reference.md) |

- [Runnable examples](./examples/README.md) — native clients, official SDKs, and standalone verification.
- [SDK tests](./TESTING.md) — test locations and commands.
- [Live E2E tests](./e2e/README.md) — real-service coverage and CI setup.
- [Release process](./RELEASING.md) — package publishing and maintainer checks.
- [Issues](https://github.com/nearai/inference-sdk/issues) — bug reports and feature requests.

## License

[MIT](./LICENSE) © NEAR AI.
