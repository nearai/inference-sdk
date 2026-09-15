# Verifiable AI SDK for TypeScript

`verifiable-ai-sdk` verifies Gateway and model attestations in Node.js and
browsers. It also provides secure Chat Completions clients for NEAR-backed
model deployments that expose a quote-bound E2EE public key.

The package has two layers:

- `SecureClient` provides standard `chat.completions.create()`, a reusable
  `fetch` for external OpenAI clients, and `verifyResponse(id)` for later verification.
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

Every `create()` and `fetch()` call retains the exact request and response
bytes before decryption. Call `verifyResponse(completion.id)` after displaying
the response to fetch and verify its signature. For streaming, finish consuming
the stream first and use its chunk ID. Concurrent requests are tracked by ID.

Response records and verification results are retained for 15 minutes after
the response finishes, controlled by `responseCacheTimeToLiveMs`. They hold
complete response bodies in memory until expiry. Verification uses the evidence
captured for that request, even if the attestation cache has since refreshed.

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
