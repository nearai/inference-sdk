# TypeScript verification guide

Use `NearAiSecureClient` when the device should verify deployment evidence and
encrypt supported Chat Completions fields directly to a verified NEAR model
key. Use `AttestationClient` plus the standalone verification functions when
your application owns the transport or needs to control each verification step
itself.

## Send an E2EE chat completion

`NearAiSecureClient` uses the official OpenAI request and response types. It
uses `signingAlgo` for Gateway/model evidence, model-key routing, optional
response receipts, and E2EE. It defaults to `ed25519`; set it to `ecdsa` for a
deployment that uses the legacy ECDSA protocol. E2EE is enabled by default.
Its E2EE runtime transforms the fields covered by the protocol and forwards the
rest to the Gateway. Each Chat request names its model; before dispatch, the
client uses a verified session for that model and the Gateway.

This direct-Gateway example is for a server-side API key. It uses the Node
entry point, which compares Gateway evidence with the TLS peer that returned
the attestation. After verification, the secure client pins its model-evidence,
Chat, and receipt-signature requests to that attested SPKI. Those requests may
use new HTTPS connections; the original TLS socket is not reused. For a browser
integration, use the aggregator configuration below with its browser
authentication headers instead.

```ts
import { NearAiSecureClient } from 'verifiable-ai-sdk/node';

const model = 'z-ai/glm-5.3-flash';
const client = new NearAiSecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
});

const completion = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});

console.log(completion.choices[0].message.content);
```

To select ECDSA instead of the default Ed25519 protocol:

```ts
const client = new NearAiSecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
  signingAlgo: 'ecdsa',
});
```

Each valid Chat request starts or joins verification for its `model` when no
valid session is cached. Successful sessions are reused for 15 minutes by
default; set `attestationCacheTimeToLiveMs: 0` to verify every request. The
client verifies every returned model candidate, then selects a verified model
key for the configured algorithm and sends it in `X-Model-Pub-Key` so the
Gateway routes the Chat request to a compatible model path.

Session reuse does not detect a deployment change until the session expires.
Set the cache lifetime to `0` when the application must re-check evidence
before every request.

The key comes from `signing_public_key`. The SDK binds it to the signer already
authenticated by the quote before using it as an encryption recipient: an
Ed25519 key must equal the signer, while an ECDSA key must derive the signer's
address.

## Decide which deployments to approve

Attestation proves measurements; it does not define your release policy.
`deploymentPolicy` is an optional callback that receives authenticated model
measurements and must throw or reject values your application does not
approve.

```ts
const client = new NearAiSecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
  deploymentPolicy: ({ model, deployment }) => {
    const expected = EXPECTED_COMPOSE_HASHES[model];
    if (
      expected === undefined ||
      deployment.runtimeMeasurements.composeHash !== expected
    ) {
      throw new Error('Unapproved model deployment');
    }
  },
});
```

Without a policy or `modelVerification.verifiers.deployment`, the SDK still
verifies the quote, nonce, event log, measurements, and available GPU evidence.
It does not claim that a deployment is release-approved. A future published
NEAR AI release policy can become the default without changing this calling
pattern.

## Use an aggregator

Set `baseUrl` to the aggregator API base URL and set the headers it expects.
The SDK sends those static headers with evidence, signature, and Chat requests.
The aggregator authenticates them and forwards requests with its own NEAR AI
credential. The device still performs attestation verification and encrypts
message fields before the aggregator receives them.

```ts
import { NearAiSecureClient } from 'verifiable-ai-sdk';

const client = new NearAiSecureClient({
  baseUrl: 'https://api.example.com/v1',
  headers: {
    Authorization: 'Bearer <browser-scoped token>',
  },
});
```

A compatible aggregator must proxy `GET /v1/attestation/report` and, when
receipt verification is used, `GET /v1/signature/{completionId}`. It
authenticates the configured client headers and substitutes its own upstream
credential. It must forward the Chat request and its model key pin unchanged.
For receipt verification, it must preserve the exact Chat request and response
entity-body bytes without parsing, reserializing, or otherwise transforming
them. When E2EE is enabled, it must also forward the encrypted body and
field-encryption headers unchanged. In production, the aggregator endpoint
should use HTTPS because client credentials are sent to it.

The generic entry point uses no TLS binding because browser Fetch cannot expose
the peer certificate. In Node.js, the `/node` secure client compares Gateway
evidence with the observed peer and pins later Gateway requests to the
attested SPKI by default. If its `baseUrl` is an aggregator or proxy instead,
disable both behaviors explicitly:

```ts
import { NearAiSecureClient } from 'verifiable-ai-sdk/node';

const client = new NearAiSecureClient({
  baseUrl: 'https://api.example.com/v1',
  headers: {
    Authorization: 'Bearer <server-scoped token>',
  },
  gatewayVerification: { includeSpkiFingerprint: false },
});
```

## E2EE scope and response handling

It is not a generic Gateway encryption layer: it requires NEAR model evidence
that supplies a quote-bound key for the selected algorithm. Ed25519, the
default, uses the version 2 field-encryption protocol. `X-Encryption-Version:
2` selects that Ed25519 wire format; it does not define an ECDSA version. ECDSA
therefore uses its secp256k1 ECDH and AES-GCM format without that header. The
secure client accepts only `POST /v1/chat/completions`; Responses API and other
endpoint paths are rejected locally before it requests attestation evidence.

The SDK transforms protocol-covered fields; it does not validate every Chat
option locally. The Gateway and model remain responsible for accepting a
request's overall shape. Every E2EE Chat request sends
`X-Encrypt-All-Fields: true`. This enables the protocol's additional documented
fields; it does not encrypt arbitrary request JSON.

| Capability | E2EE behavior |
| --- | --- |
| String `messages[].content` | Each string is encrypted independently. |
| Rich message content | An array-valued `messages[].content` is serialized and encrypted as one value. |
| Assistant context | String `reasoning_content`, `reasoning`, and `audio.data` message fields are encrypted. |
| Function and tool fields | Recognized function definitions, function calls, and related message fields are encrypted. Other tool forms are preserved without E2EE transformation. |
| `web_context_search` | The request is forwarded normally; supported search-tool output is decrypted. The Gateway decides whether a particular streaming or non-streaming request is valid. |
| Other Chat request-body fields | Preserved without E2EE transformation. The Gateway and model decide whether to accept them. Fields outside the protocol are ordinary request data, not E2EE-protected values. |
| Non-streaming and streaming Chat | The client checks the AEAD tag of each non-empty protocol-covered assistant and tool value before decrypting it. For streaming, it waits until each SSE event is complete, even when the event spans transport chunks. |

Each non-empty protocol-covered encrypted response field must pass its AEAD
integrity check before the client decrypts it. This checks the encrypted field
within the E2EE protocol; it does not establish that a particular Gateway or
model signer produced the response. Ordinary
`chat.completions.create()` does not fetch or verify a completion receipt before
returning its decrypted result.
Field-level AEAD integrity checking is necessary before plaintext can be
displayed; receipt verification is a separate byte-level check. A receipt cannot
prevent a request that has already been sent, and waiting for one would
needlessly delay a user-visible message.

The field-encryption protocol covers only the recognized Chat JSON values. URL
query parameters and caller-supplied headers remain ordinary transport
metadata, so do not place private prompt or tool data there.

Non-2xx responses are returned without E2EE decryption and follow the normal
OpenAI client error path.

### Stream an E2EE completion

```ts
const stream = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
  stream: true,
});

for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta.content ?? '');
}
```

### Send plaintext after deployment verification

Set `e2ee: false` only when field encryption is not needed. This does not turn
off the deployment gate: verification and `deploymentPolicy` run whenever the
model's cached session is missing or expired.

```ts
const client = new NearAiSecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
  e2ee: false,
});
```

In this mode the client sends plaintext Chat fields and response. It does not
encrypt or decrypt fields, but still sends a model-key routing header for the
selected algorithm. A model that does not expose that key is not supported by
the secure client, even in plaintext mode. A successful deployment check does
not prove that these particular request and response bytes were signed by an
attested Gateway or model.

## Verify a response receipt

Use `createWithReceipt()` when the application also needs to verify the exact
Chat request and response bodies. It preserves the Fetch entity-body bytes
before E2EE decryption, so the rendered completion can remain on the normal UI
path while receipt verification happens later.

```ts
const { completion, receipt } =
  await client.chat.completions.createWithReceipt({
    model,
    messages: [{ role: 'user', content: 'Hello' }],
  });

render(completion.choices[0]?.message.content);

const verified = await receipt.verify();
console.log(verified.signatureKind);
```

`receipt.requestBody` is immediately available. `receipt.responseBody` resolves
to the exact response bytes after the response finishes; for E2EE, both are the
encrypted bytes, not reconstructed plaintext JSON. Do not parse and reserialize
either body. `receipt.verify()` waits for those bytes, retrieves the completion
signature for the configured algorithm, and selects the matching evidence from
the verified session used for this Chat request.

For `fetchWithReceipt()`, consume the returned `Response` body before calling
`receipt.verify()`. For a stream, consume or drain the returned stream first.
Until then, the receipt cannot have the complete response bytes.
Receipt mode retains the complete request and response bodies in memory, so use
it for bounded responses rather than unbounded streams.

For a stream, the receipt is also available immediately and does not delay
chunk rendering:

```ts
const { stream, receipt } = await client.chat.completions.createWithReceipt({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
  stream: true,
});

for await (const chunk of stream) {
  renderIncrementally(chunk);
}

const verified = await receipt.verify();
```

`provider_tee` means the matching verified model signer signed these bytes.
`gateway` means the verified Gateway signer signed the client-visible bytes.
They establish different trust boundaries: a Gateway receipt does not by itself
show which model produced the response.

## Advanced: own the transport and verification steps

The manual flow has distinct stages:

1. Verify Gateway and model deployment evidence before sending a request.
2. Send the request and retain the exact body bytes sent and received.
3. Fetch the completion signature later and verify it against the retained
   evidence and bytes.

### Verify Gateway and model evidence

```ts
import {
  AttestationClient,
  createPinnedTlsFetch,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from 'verifiable-ai-sdk/node';

const model = 'z-ai/glm-5.3-flash';
const client = new AttestationClient({ apiKey: process.env.NEARAI_API_KEY! });

const fetchedGateway = await client.fetchGatewayAttestation({
  signingAlgo: 'ed25519',
});
const gateway = await verifyGatewayAttestation({
  attestation: fetchedGateway.attestation,
  clientBinding: fetchedGateway.clientBinding,
});
if (gateway.tlsBinding.kind !== 'attested') {
  throw new Error('Expected TLS-bound Gateway evidence');
}
const pinnedTlsFetch = createPinnedTlsFetch(
  gateway.tlsBinding.spkiFingerprint,
);

const fetchedModels = await client.fetchModelAttestations({
  model,
  signingAlgo: 'ed25519',
});
if (fetchedModels.attestations.length === 0) {
  throw new Error('Gateway returned no model attestation');
}

const models = await Promise.all(
  fetchedModels.attestations.map((attestation) =>
    verifyModelAttestation({
      attestation,
      clientBinding: fetchedModels.clientBinding,
    }),
  ),
);
```

Use `pinnedTlsFetch` instead of `fetch` for raw direct-Gateway requests that
your application sends itself. It performs normal certificate and hostname
verification, then requires each TLS peer to present the attested SPKI.

The generic `verifiable-ai-sdk` entry point requests the no-TLS Gateway quote
layout and is suitable for browsers. The `/node` `AttestationClient` observes
only the peer for its Gateway-attestation request; it does not automatically
apply `pinnedTlsFetch` to its model or signature helpers. Use the Node secure
client when the complete Chat flow—including model evidence, completion, and
receipt signature—must be pinned automatically.

### Verify a later receipt

`signature.kind` identifies the signer and therefore the proof made by a
successful verification:

| Kind | Verify with | Establishes |
| --- | --- | --- |
| `provider_tee` | A matching verified model attestation | The model-serving TEE signer signed the exact request and response body bytes. |
| `gateway` | The verified Gateway attestation | The Gateway signer signed the exact client-visible request and response body bytes. |

For an E2EE request, preserve the encrypted JSON body bytes—not the plaintext
object after decryption. Do not parse and reserialize either body before
verification.

```ts
import {
  findModelAttestationForSignature,
  verifyGatewayResponse,
  verifyModelResponse,
} from 'verifiable-ai-sdk/node';

const signature = await client.fetchCompletionSignature({
  completionId,
  signingAlgo: 'ed25519',
});

if (signature.kind === 'provider_tee') {
  verifyModelResponse({
    requestBody,
    responseBody,
    signature,
    attestation: findModelAttestationForSignature({
      attestations: models,
      signature,
    }),
  });
} else {
  verifyGatewayResponse({
    requestBody,
    responseBody,
    signature,
    attestation: gateway,
  });
}
```

`provider_tee` and `gateway` describe different trust boundaries. A Gateway
receipt does not independently establish that an upstream model generated the
final response, and a provider receipt does not bind its bytes to verified
Gateway deployment evidence. The planned paired provider signature and Gateway
receipt for rewritten responses are tracked in
[cloud-api#986](https://github.com/nearai/cloud-api/issues/986).

## Handle errors

`AttestationClient` and selection helpers throw `ApiError` for SDK-classified
request, response, nonce, and selection problems. Explicit `verify…` calls
and E2EE integrity-check or decryption failures throw `VerificationError`.
Check the stable `failure.code` rather than parsing an error message.

```ts
import { ApiError } from 'verifiable-ai-sdk';

try {
  await client.fetchCompletionSignature({ completionId });
} catch (error) {
  if (!(error instanceof ApiError)) throw error;
  console.log(error.failure.code);
}
```
