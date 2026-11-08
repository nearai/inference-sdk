<p align="center">
  <img src="./.github/assets/readme-banner.svg" alt="NEAR AI Inference SDK — Private inference. Verifiable responses." width="100%">
</p>

<p align="center">
  <strong>Build with familiar APIs. Verify the infrastructure and the response.</strong><br>
  Attestation, response signatures, and optional encryption for NEAR AI Cloud.<br>
  Available in TypeScript, Python, Rust, and Go.
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

## Why NEAR AI Inference SDK?

- **Verify before you send.** Check the Gateway's attestation and supported model
  deployments before inference, with reusable verification caches.
- **Verify what comes back.** Check response signatures against the exact request
  and response bytes retained by the client, including streamed responses.
- **Add encryption where you need it.** Enable field-level end-to-end encryption
  (E2EE) for supported Chat models, or OHTTP for the HTTP exchange with the Gateway.
- **Keep familiar APIs.** Use Chat Completions, Responses, Anthropic Messages, and
  System One across all four languages, with official SDK integrations where
  available.

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
2. **Send the request.** The client retains the exact request and response bytes
   needed for signature verification. E2EE and OHTTP are optional and disabled by
   default; their scope depends on the API.
3. **Verify the response.** Use the SDK's response verification before using the
   answer. For streaming, consume the entire stream first.

A `provider_tee` signature binds those bytes to an attested model signer; a
`gateway` signature binds them to an attested Gateway signer. Gateway signatures
do not prove model TEE execution. See the [verification guides](#documentation)
for encryption scope, deployment policies, and trust boundaries.

Use **Gateway clients for production integrations**. Direct model clients are
experimental; see the limitations for
[TypeScript](./js/docs/verification-guide.md#use-a-direct-model-endpoint),
[Python](./py/docs/verification-guide.md#direct-model-endpoints),
[Rust](./rs/docs/verification-guide.md#experimental-direct-endpoints), and
[Go](./go/docs/verification-guide.md#experimental-direct-endpoints).

## Documentation

| SDK | Verification guide | API reference |
| --- | --- | --- |
| **TypeScript / JavaScript** | [Encryption, streaming & policies](./js/docs/verification-guide.md) | [Types & methods](./js/docs/api-reference.md) |
| **Python** | [Encryption, streaming & policies](./py/docs/verification-guide.md) | [Types & methods](./py/docs/api-reference.md) |
| **Rust** | [Encryption, streaming & policies](./rs/docs/verification-guide.md) | [Types & methods](./rs/docs/api-reference.md) |
| **Go** | [Encryption, streaming & policies](./go/docs/verification-guide.md) | [Types & methods](./go/docs/api-reference.md) |

- [Live E2E tests](./e2e/README.md) — real-service coverage and CI setup.
- [Release process](./RELEASING.md) — package publishing and maintainer checks.
- [Issues](https://github.com/nearai/inference-sdk/issues) — bug reports and feature requests.

## License

[MIT](./LICENSE) © NEAR AI.
