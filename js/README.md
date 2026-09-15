# Verifiable AI SDK for TypeScript

`verifiable-ai-sdk` verifies Gateway and model attestations in Node.js and
browsers. It also provides secure Chat Completions clients for NEAR-backed
model deployments that expose a quote-bound E2EE public key.

The package has two layers:

- `NearAiSecureClient` exposes the familiar OpenAI Chat Completions shape,
  including `createWithReceipt()` for an asynchronous response audit;
  `SecureClient` exposes the same deployment-checked request path as `fetch`.
- `AttestationClient` and the standalone `verify…` functions let applications
  fetch, inspect, and verify evidence or completion receipts themselves.

## Secure Chat Completions

Each valid `SecureClient.fetch()` call uses a successfully verified
Gateway/model session for the `model` named in that Chat request. Sessions are
retained for 15 minutes by default; set `attestationCacheTimeToLiveMs: 0` to
verify every request. A cache miss runs any caller-supplied deployment policy.
Reuse does not observe a deployment change until the session expires; use `0`
when each request must re-check current evidence.
If verification or policy approval fails, no inference request is sent.

`signingAlgo` selects the Gateway/model evidence, model-key routing, optional
response receipt, and E2EE protocol. It defaults to `ed25519`; set it to
`ecdsa` for a deployment that uses the legacy ECDSA protocol.

E2EE is enabled by default:

| `e2ee` | What the client does after verification |
| --- | --- |
| `true` or omitted | Encrypts supported request fields to a quote-bound model key for the selected algorithm, pins the request to that key, and decrypts protocol-covered response fields. |
| `false` | Sends plaintext Chat fields with a verified model-key routing header for the selected algorithm. Attestation and deployment-policy checks still run on a cache miss, but this alone does not prove the exact response bytes. |

The default Ed25519 transport uses the version 2 field-encryption protocol.
ECDSA uses the legacy secp256k1 ECDH and AES-GCM protocol and does not send
`X-Encryption-Version: 2`. Both use a key bound to verified model evidence.
The client supports only `POST /chat/completions`, in non-streaming and
streaming modes, and encrypts the request fields it recognizes: string message content,
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
checks its AEAD tag. This field-level integrity check is not a completion
receipt and does not establish that a particular Gateway or model signer
produced the response.

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
