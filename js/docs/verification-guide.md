# TypeScript guide

Start with the [quick start](../README.md#quick-start) for a non-streaming Chat
request. The examples here use the same `NEARAI_API_KEY` environment variable
and Node.js 24+. Save a complete example as `example.mts` and run
`node example.mts`.

- [Stream a response](#stream-an-e2ee-completion)
- [Use the OpenAI SDK](#use-the-official-openai-sdk)
- [Verification and caching](#cache-deployment-verification)
- [Encryption](#e2ee-scope-and-response-handling)
- [Policies and image provenance](#set-verification-policy)
- [Browser and proxy setup](#connect-through-an-application-proxy)
- [Manual verification](#verify-gateway-requests-manually)
- [Direct endpoints](#use-a-direct-model-endpoint)
- [Errors](#handle-errors)

For option and result fields, see the [API reference](./api-reference.md).

## What verification proves

Before sending Chat, the client verifies the Gateway and every returned model
attestation for supported NEAR TEE models. Those checks authenticate the signing
keys, Intel TDX quotes, nonces, and measured deployment configuration. Model
checks also verify NVIDIA GPU evidence when present.

Models without supported model attestation use **Incognito** mode: only the
Gateway is verified. E2EE and model deployment policies require model evidence,
so they reject Incognito models. A failed model check never falls back to
Gateway-only verification.

Attestation checks a deployment. A response signature connects the exact
request and response bytes to a verified signer:

| Signature kind | What response verification proves |
| --- | --- |
| `provider_tee` | A verified model TEE signer signed the request and response bytes. |
| `gateway` | A verified Gateway signer signed the client-visible bytes. This does not prove model execution. |

The Gateway may sign a response after rewriting it, such as normalizing streaming
usage fields. In that case the original model signature cannot verify the
rewritten bytes. The client selects the response verifier from the returned
signature kind. Verifying both deployments does not add a missing model signature
to a Gateway-signed response ([tracking issue](https://github.com/nearai/cloud-api/issues/986)).

## Stream an E2EE completion

Consume the full stream, then verify it using the completion ID from its chunks.
This example displays tokens as they arrive, before signature verification.
Buffer them instead if your application must display only verified output.

```ts
import { InferenceClient } from '@nearai/inference-sdk/node';

async function main() {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('Set NEARAI_API_KEY');

  const client = new InferenceClient({ apiKey, e2ee: true });
  const stream = await client.chat.completions.create({
    model: 'z-ai/glm-5.3-flash',
    messages: [{ role: 'user', content: 'Write a short greeting.' }],
    stream: true,
  });

  let completionId: string | undefined;
  for await (const chunk of stream) {
    completionId = chunk.id;
    process.stdout.write(chunk.choices[0]?.delta.content ?? '');
  }
  console.log();

  if (!completionId) throw new Error('Stream returned no completion ID');
  const verified = await client.verifyResponse(completionId);
  console.log(`Verified ${verified.signatureKind} response`);
}

await main();
```

`verifyResponse()` uses the request and response bytes captured by the client,
including encrypted bytes when E2EE is enabled. It does not send Chat again.

## Use the official OpenAI SDK

Install `openai` alongside this SDK. Pass the inference client's Fetch adapter
to OpenAI, and verify the response through the same inference client:

```ts
import OpenAI from 'openai';
import { InferenceClient } from '@nearai/inference-sdk/node';

async function main() {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('Set NEARAI_API_KEY');

  const inferenceClient = new InferenceClient({ apiKey, e2ee: true });
  const openai = new OpenAI({
    apiKey,
    baseURL: inferenceClient.getBaseUrl(),
    fetch: inferenceClient.fetch,
  });

  const completion = await openai.chat.completions.create({
    model: 'z-ai/glm-5.3-flash',
    messages: [{ role: 'user', content: 'Hello!' }],
  });
  await inferenceClient.verifyResponse(completion.id);
  console.log(completion.choices[0]?.message.content ?? '');
}

await main();
```

The adapter supports Chat Completions, including streaming, not the Responses
API. Configure authentication on `InferenceClient`; its credentials take
precedence over those supplied by the OpenAI client.

## Cache deployment verification

Reuse a client across requests. Successful deployment checks are cached per
model for 60 minutes. To verify while a user selects a model, put this call
before Chat in the quick start:

```ts
const deployments = await client.verify('z-ai/glm-5.3-flash');
console.log(deployments.gateway.tcbStatus);
console.log(deployments.models.map((model) => model.tcbStatus));
```

This sends no Chat request. It returns the same verified evidence used by Chat,
and concurrent calls for the same model share in-flight verification.

To change the cache duration, replace the quick start's client construction:

```ts
const client = new InferenceClient({
  apiKey,
  e2ee: true,
  attestationCacheTimeToLiveMs: 15 * 60 * 1000,
  responseCacheTimeToLiveMs: 5 * 60 * 1000,
});
```

Set `attestationCacheTimeToLiveMs: 0` to verify before every request, even after
an explicit `verify()`. Cached checks do not detect deployment changes until
they expire.

The response cache is separate. It retains complete request and response bodies
in memory, and its TTL starts when the response finishes. Call
`verifyResponse(id)` before expiry. Unknown or expired IDs fail with
`api.completion_not_found`.

## E2EE scope and response handling

Set `e2ee: true` to encrypt supported Chat fields to a verified model key.
Leave it off to send plaintext over HTTPS while keeping deployment and response
verification available.

E2EE covers message content, including rich-content arrays, reasoning fields,
audio data, and supported tool/function fields. Other fields, URL parameters,
and HTTP headers are not field-encrypted. Decryption checks the encrypted
message's authentication tag; response-signature verification remains a
separate `verifyResponse()` call.

`signingAlgo` selects one algorithm for attestation, model-key routing,
encryption, and response signatures. It defaults to `'ed25519'`.
To use ECDSA, change the client construction:

```ts
const client = new InferenceClient({
  apiKey,
  e2ee: true,
  signingAlgo: 'ecdsa',
});
```

Ed25519 encryption uses XChaCha20-Poly1305 and `X-Encryption-Version: 2`.
ECDSA uses secp256k1 ECDH with AES-GCM and omits that header because version 2
selects the Ed25519 protocol. Both modes enable `X-Encrypt-All-Fields` for the
supported fields listed above.

### Use OHTTP

Add `ohttp: true` to the client options to encrypt the Chat HTTP exchange to
the Gateway. Keep the default Ed25519 algorithm; OHTTP does not support ECDSA.
Chat, streaming, and response-verification calls stay the same.

OHTTP and model E2EE protect different parts of a request. They can be enabled
together, or OHTTP can be used alone with Incognito models. The endpoint must
serve `/ohttp` at its origin and provide a signed key configuration, which the
client verifies before use.

Metadata, attestation, and signature lookups do not use OHTTP. Authorization and
configured custom headers are also sent on the outer request. OHTTP does not
hide them or the client's network address from that endpoint.

## Set verification policy

The default policy accepts `UpToDate` and `OutOfDate` Intel TCB statuses and
verifies GPU evidence when present. To require an up-to-date platform and GPU
evidence, use these options in the quick start:

```ts
const client = new InferenceClient({
  apiKey,
  e2ee: true,
  gatewayVerification: {
    policy: { acceptedTcbStatuses: ['UpToDate'] },
  },
  modelVerification: {
    policy: {
      acceptedTcbStatuses: ['UpToDate'],
      gpuEvidence: 'required',
    },
  },
});
```

These checks authenticate measurements but do not approve a software release.
Use `deploymentPolicy` to compare each model's authenticated measurements with
your own allowlist. The callback receives the requested model and its measured
deployment; throw to reject it. There is no built-in release allowlist.

### Optional image build provenance

A deployment callback can also check measured container images against their
published GitHub build proofs. This configuration checks one Gateway image.
Add the imports and replace the client construction in the quick start:

```ts
import { verifyDeploymentImageProvenance } from '@nearai/inference-sdk/node';

const client = new InferenceClient({
  apiKey,
  e2ee: true,
  gatewayVerification: {
    verifiers: {
      deployment: async ({ appCompose }) => {
        await verifyDeploymentImageProvenance({
          appCompose,
          imagePolicies: {
            'nearaidev/cloud-api': {
              repository: 'nearai/cloud-api',
              workflow: '.github/workflows/build.yml',
            },
          },
        });
      },
    },
  },
});
```

The callback runs after the configuration is authenticated by attestation.
Every image repository in the policy must be present and digest-pinned.
Unlisted images are not checked. A valid build proof establishes the repository,
workflow, and source commit; add an approved `commit` to restrict accepted
versions. This is not proof of the containers currently running after boot.

The [client example](../../examples/example-js/gateway/client.ts) checks four
Gateway images. Those policies are example configuration, not SDK defaults or
model-image policies. For reusable workflows and other policy fields, see
[image build provenance](./api-reference.md#image-build-provenance).

## Connect through an application proxy

Keep the NEAR API key on your backend. Forward metadata, attestation, Chat, and
signature requests without rewriting bodies or dropping model-routing and
encryption headers.

For browser applications, import the generic entry point. Browsers cannot read
the TLS peer certificate, so this client does not perform attested TLS pinning.
Normal browser HTTPS validation still applies. NVIDIA verification also needs a
CORS-enabled proxy; the example uses placeholder URLs for your backend:

```ts
import {
  InferenceClient,
  createGpuEvidenceVerifier,
} from '@nearai/inference-sdk';

export function createBrowserClient(applicationToken: string) {
  const gpuEvidence = createGpuEvidenceVerifier({
    nrasUrl: 'https://api.example.com/attestation/gpu',
    jwksUrl: 'https://api.example.com/attestation/jwks',
  });

  return new InferenceClient({
    baseUrl: 'https://api.example.com/v1',
    headers: { Authorization: `Bearer ${applicationToken}` },
    e2ee: true,
    modelVerification: { verifiers: { gpuEvidence } },
  });
}
```

Your application passes its own login token to this factory and uses the
returned client as in the quick start. Some browser bundlers also need Node
compatibility polyfills for transitive dependencies.

The inference proxy must forward `/v1/model/{model}`,
`/v1/attestation/report`, `/v1/chat/completions`, and `/v1/signature/{id}`.
Preserve URL-encoded IDs. With OHTTP, also forward `/ohttp`.

In Node.js, if your proxy terminates TLS, set
`gatewayVerification: { includeSpkiFingerprint: false }`: the proxy's
certificate is not the attested Gateway's. This disables attested TLS binding,
not HTTPS certificate validation.

### Configure attestation service URLs

The quote verifier uses Intel's collateral service in Node.js and Phala's
PCCS in browsers. NVIDIA verification uses NRAS and NVIDIA's JWKS by default.
To override them, add these imports and client options to the quick start:

```ts
import {
  createTdxQuoteVerifier,
  createGpuEvidenceVerifier,
} from '@nearai/inference-sdk/node';

const tdxQuote = createTdxQuoteVerifier({
  pccsUrl: 'https://attestation.example.com',
});
const gpuEvidence = createGpuEvidenceVerifier({
  nrasUrl: 'https://attestation.example.com/v3/attest/gpu',
  jwksUrl: 'https://attestation.example.com/.well-known/jwks.json',
});
const client = new InferenceClient({
  apiKey,
  e2ee: true,
  gatewayVerification: { verifiers: { tdxQuote } },
  modelVerification: { verifiers: { tdxQuote, gpuEvidence } },
});
```

A PCCS proxy must preserve collateral bodies and issuer-chain headers for the
SGX and TDX v4 paths. Serve the hex-encoded root CRL at
`/sgx/certification/v4/rootcacrl` to avoid a direct CRL fallback.

Changing URLs does not disable cryptographic checks. A custom JWKS endpoint
does select the trusted source of NVIDIA signing keys, so use only a trusted
proxy. An issuer check alone cannot authenticate keys from an arbitrary server.

## Verify Gateway requests manually

Use `AttestationClient` and standalone verifiers when you need to inspect
evidence or control when checks run. This complete example audits deployments
without sending Chat:

```ts
import {
  AttestationClient,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '@nearai/inference-sdk/node';

async function main() {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('Set NEARAI_API_KEY');
  const client = new AttestationClient({ apiKey });

  const fetchedGateway = await client.fetchGatewayAttestation({
    signingAlgo: 'ed25519',
  });
  const gateway = await verifyGatewayAttestation(fetchedGateway);
  console.log(`Gateway TCB: ${gateway.tcbStatus}`);

  const fetchedModels = await client.fetchModelAttestations({
    model: 'z-ai/glm-5.3-flash',
    signingAlgo: 'ed25519',
  });
  if (fetchedModels.attestations.length === 0) {
    throw new Error('No model attestations returned');
  }
  for (const attestation of fetchedModels.attestations) {
    const model = await verifyModelAttestation({
      attestation,
      clientBinding: fetchedModels.clientBinding,
    });
    console.log(`Model TCB: ${model.tcbStatus}; GPU: ${model.gpuEvidence}`);
  }
}

await main();
```

Fetch generates a fresh nonce and checks the echoed value. Verification
authenticates that nonce in the quote along with the signer and measurements.
Gateway evidence also binds the observed TLS key in Node.js. Model evidence
retrieved through the Gateway has no client-to-model TLS binding.

To verify a Chat response manually, follow the complete
[bare example](../../examples/example-js/gateway/bare.ts). It verifies
deployments first, encrypts and sends Chat, saves the exact encrypted request
and response bytes, decrypts the response, and verifies its signature. It
includes both JSON and streaming calls.

Keep the same explicit signing algorithm for attestation and signature fetches;
the service endpoints have different defaults. Verify every fetched model
report before Chat. Later, `findModelAttestationForSignature` selects the
verified model matching a `provider_tee` signature. A `gateway` signature
uses the verified Gateway result instead.

### Encrypt a raw Chat request

For application-owned HTTP requests, `prepareE2eeChatRequest` takes a
`Request` and an already verified model public key. It returns an encrypted
request and its paired JSON/SSE response decryptor. It does not verify the
attestation or send the request.

The bare example shows key selection and byte capture. Response verification
uses the encrypted bytes, not decrypted or reserialized JSON. In Node.js,
`createPinnedTlsFetch` can bind application-owned requests to the previously
verified Gateway SPKI.

## Use a direct model endpoint

Direct clients are experimental and not recommended for production. They verify
model evidence without Gateway attestation or catalog lookup.

`DirectInferenceClient` takes the model endpoint's `baseUrl` and defaults
to E2EE enabled. Chat, streaming, OpenAI integration, and response verification
use the same interfaces as the Gateway client.
See the runnable [direct client](../../examples/example-js/direct/client.ts)
and [manual verification](../../examples/example-js/direct/bare.ts) examples.

Direct clients currently request no TLS fingerprint and perform no attested
TLS pinning. Standard HTTPS validation remains enabled. Reports may omit other
serving instances, and a signature lookup may return 404 when it reaches a
different instance ([endpoint limitations](https://github.com/nearai/cloud-api/issues/1087)).
Every report returned is still verified.

## Handle errors

Deployment verification failures stop Chat before it is sent. Response
verification failures happen after receiving content.

The built-in Chat interface and external OpenAI clients preserve OpenAI's error
behavior. A transport failure is wrapped in `APIConnectionError`; its
`cause` contains the SDK error. `client.fetch()` and
`client.verifyResponse()` expose SDK errors directly.

Add these imports and replace the verification and output lines in the quick start:

```ts
import { ApiError, VerificationError } from '@nearai/inference-sdk/node';

try {
  await client.verifyResponse(completion.id);
  console.log(completion.choices[0]?.message.content ?? '');
} catch (error) {
  if (error instanceof ApiError || error instanceof VerificationError) {
    console.error(error.failure.code);
  }
  throw error;
}
```

Use the structured failure code for application decisions. `retryable` means
a failed external operation may succeed on another attempt, not that Chat
should be replayed. An expired response record cannot be recovered by retrying
verification.

In a manual flow, fetching and selecting evidence raise `ApiError`;
verification functions raise `VerificationError`.
