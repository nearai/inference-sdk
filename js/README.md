# Verifiable AI SDK for TypeScript

`verifiable-ai-sdk` verifies Gateway and model attestations in Node.js and
browsers. It also provides secure Chat Completions clients for NEAR-backed
model deployments that expose a quote-bound Ed25519 public key.

The package has two layers:

- `NearAiSecureClient` exposes the familiar OpenAI Chat Completions shape,
  including `createWithReceipt()` for an asynchronous response audit;
  `SecureClient` exposes the same deployment-checked request path as `fetch`.
- `AttestationClient` and the standalone `verify…` functions let applications
  fetch, inspect, and verify evidence or completion receipts themselves.

## Secure Chat Completions

Each valid `SecureClient.fetch()` call starts or joins a fresh Gateway/model
verification for the `model` named in that Chat request before it sends it. It
also runs any caller-supplied deployment policy with that model. Completed
evidence is never cached. If verification or policy approval fails, no
inference request is sent.

Secure clients use Ed25519 only for Gateway/model evidence and optional
response receipts; the signing algorithm is not configurable.

E2EE is enabled by default:

| `e2ee` | What the client does after verification |
| --- | --- |
| `true` or omitted | Encrypts supported request fields to a quote-bound Ed25519 model key, pins the request to that key, and decrypts protocol-covered response fields. |
| `false` | Sends plaintext Chat fields with a verified Ed25519 model-key routing header. Fresh attestation and deployment-policy checks still run, but this alone does not prove the exact response bytes. |

The E2EE transport uses NEAR model evidence with a quote-bound Ed25519 key and
the version 2 field-encryption protocol. It supports only
`POST /chat/completions`, in non-streaming and streaming modes. The client
encrypts the request fields it recognizes: string message content,
array-valued rich message content, assistant reasoning and audio data, and
recognized function and tool values.
Every E2EE Chat request sends `X-Encrypt-All-Fields: true`; that enables the
protocol's additional documented fields but does not turn arbitrary JSON into
ciphertext.

Other Chat fields and unrecognized values are preserved without E2EE
transformation. The Gateway and model decide whether to accept them; the SDK is
not a second Chat request validator. A field that the protocol does not
recognize is not automatically encrypted, so place private data only in fields
covered by the E2EE flow.

Before decrypting a non-empty protocol-covered response field, the client
checks its XChaCha20-Poly1305 AEAD tag. This field-level integrity check is not a
completion receipt and does not establish that a particular Gateway or model
signer produced the response.

Ordinary `create()` and `fetch()` calls do not fetch a completion receipt on the
request path. Use `createWithReceipt()` or `fetchWithReceipt()` when an
asynchronous byte-level audit is needed. They preserve Fetch entity-body bytes
before E2EE decryption; `receipt.verify()` later retrieves and verifies the
matching completion signature without reissuing inference. A receipt cannot
prevent an already-sent request and should not delay a user-visible response.

## Documentation

- [Verification guide](./docs/verification-guide.md) explains secure Chat,
  E2EE, aggregators, policies, and optional receipt verification.
- [API reference](./docs/api-reference.md) lists the clients, types, and
  standalone verification functions.

## Runtime

The package publishes ESM and is developed with Node.js 24. Import from
`verifiable-ai-sdk/node` for a direct Gateway connection in Node.js. Its
`AttestationClient` compares Gateway evidence with the peer that returned the
attestation. After that check, its secure Chat clients pin model-evidence,
Chat, and receipt-signature requests to the attested SPKI. Each request may
use a new HTTPS connection; it does not need to reuse the attestation socket.
Import from `verifiable-ai-sdk` when peer-certificate observation is
unavailable, including browsers; its clients use the no-TLS Gateway-evidence
layout. A Node client that connects through an aggregator or proxy should set
`gatewayVerification.includeSpkiFingerprint` to `false`, which disables both
the peer comparison and later request pinning.

The default Intel verifier may require `crypto`, `buffer`, and `stream`
polyfills in browsers. Supply a custom quote verifier when your runtime or
trust model requires one.
