import {
  AttestationClient,
  createPinnedTlsFetch,
  prepareE2eeChatRequest,
  verifyDeploymentImageProvenance,
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '@nearai/inference-sdk/node';
import type {
  E2eeModelKey,
  GatewayTlsBinding,
  ImageProvenancePolicy,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from '@nearai/inference-sdk/node';

// This example composes the SDK's standalone APIs: verify deployments, encrypt
// and send Chat requests, decrypt responses, then verify their signatures.
const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = 'ed25519';

// These policies require GitHub build provenance for four Gateway images,
// not model runtime images. Add a reviewed `commit` to pin a specific build.
const GATEWAY_IMAGE_POLICIES: Record<string, ImageProvenancePolicy> = {
  'nearaidev/cloud-api': {
    repository: 'nearai/cloud-api',
    workflow: '.github/workflows/build.yml',
  },
  'nearaidev/cvm-ingress': {
    repository: 'nearai/cvm-ingress',
    workflow: '.github/workflows/build-push.yml',
  },
  'nearaidev/dstack-vpc': {
    repository: 'nearai/dstack-vpc',
    workflow: '.github/workflows/build.yml',
  },
  'nearaidev/dstack-vpc-client': {
    repository: 'nearai/dstack-vpc-client',
    workflow: '.github/workflows/build.yml',
  },
};

await main();

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) {
    throw new Error('NEARAI_API_KEY is required');
  }

  const client = new AttestationClient({ apiKey, baseUrl: BASE_URL });

  // Verify the Gateway and every returned model report before sending a prompt.
  // A failed check throws and stops this flow before either Chat request.
  const gateway = await fetchAndVerifyGateway(client);
  const models = await fetchAndVerifyModelAttestations(client);

  // Encryption needs only the verified public key and its algorithm. Keep the
  // full model verification result separately for the response signature check.
  const model = findModelAttestationForEncryption(models);
  const modelKey: E2eeModelKey = {
    signingAlgo: model.signer.signingAlgo,
    publicKey: model.signingPublicKey,
  };

  // TLS pinning is recommended in Node. In browsers, use regular fetch instead;
  // browser APIs do not expose the TLS peer certificate needed for this check.
  const pinnedTlsFetch = createGatewayPinnedTlsFetch(gateway.tlsBinding);

  // Non-streaming: decrypt and display the JSON response, then verify its signature.
  // To display only verified output, defer rendering until verification succeeds.
  const nonStreamingCompletion = await runNonStreamingExample({
    apiKey,
    pinnedTlsFetch,
    modelKey,
  });
  await verifyCompletionResponse({
    client,
    completion: nonStreamingCompletion,
    gateway,
    model,
  });

  // Streaming: display decrypted SSE as it arrives. Signature verification needs
  // the complete response bytes, so it runs after the stream finishes.
  const streamingCompletion = await runStreamingExample({
    apiKey,
    pinnedTlsFetch,
    modelKey,
  });
  await verifyCompletionResponse({
    client,
    completion: streamingCompletion,
    gateway,
    model,
  });
}

async function runNonStreamingExample({
  apiKey,
  pinnedTlsFetch,
  modelKey,
}: CompletionExampleParams): Promise<Completion> {
  return sendCompletion({
    apiKey,
    stream: false,
    pinnedTlsFetch,
    modelKey,
  });
}

async function runStreamingExample({
  apiKey,
  pinnedTlsFetch,
  modelKey,
}: CompletionExampleParams): Promise<Completion> {
  return sendCompletion({
    apiKey,
    stream: true,
    pinnedTlsFetch,
    modelKey,
  });
}

async function fetchAndVerifyGateway(
  client: AttestationClient,
): Promise<VerifiedGatewayAttestation> {
  // The Node client generates a fresh nonce and records the TLS peer's SPKI.
  // Fetching alone does not verify the returned evidence.
  const fetched = await client.fetchGatewayAttestation({
    signingAlgo: SIGNING_ALGO,
  });
  // Verify the quote, nonce, measurements, and signer/TLS binding. The deployment
  // callback checks image provenance after appCompose has been authenticated.
  const verified = await verifyGatewayAttestation({
    attestation: fetched.attestation,
    clientBinding: fetched.clientBinding,
    verifiers: {
      deployment: ({ appCompose }) =>
        verifyDeploymentImageProvenance({
          appCompose,
          imagePolicies: GATEWAY_IMAGE_POLICIES,
        }),
    },
  });
  console.log('Gateway deployment and image provenance: verified.');
  return verified;
}

async function fetchAndVerifyModelAttestations(
  client: AttestationClient,
): Promise<readonly VerifiedModelAttestation[]> {
  // These reports come through the Gateway, not a direct model TLS connection.
  // The fetch helper requests the signer-and-nonce layout without a TLS binding.
  const fetched = await client.fetchModelAttestations({
    model: MODEL,
    signingAlgo: SIGNING_ALGO,
  });
  if (fetched.attestations.length === 0) {
    throw new Error('Gateway returned no model attestations');
  }

  // All reports share the fetch helper's nonce. Verify each report's quote,
  // measurements, signing key, and GPU evidence when present before choosing a key.
  const verified = await Promise.all(
    fetched.attestations.map((attestation) =>
      verifyModelAttestation({
        attestation,
        clientBinding: fetched.clientBinding,
      }),
    ),
  );
  console.log(`Model deployments: verified ${verified.length}.`);
  return verified;
}

function findModelAttestationForEncryption(
  attestations: readonly VerifiedModelAttestation[],
): ModelAttestationWithPublicKey {
  // Choose an encryption recipient before Chat; there is no response signature
  // to select by yet. The E2EE helper also uses this key in the model-routing header.
  const attestation = attestations.find(
    (candidate): candidate is ModelAttestationWithPublicKey =>
      candidate.signer.signingAlgo === SIGNING_ALGO &&
      candidate.signingPublicKey !== undefined,
  );
  if (attestation === undefined) {
    throw new Error('No verified model public key is available for E2EE');
  }
  return attestation;
}

async function sendCompletion({
  apiKey,
  stream,
  pinnedTlsFetch,
  modelKey,
}: SendCompletionParams): Promise<Completion> {
  const request = new Request(new URL('chat/completions', BASE_URL), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'identity',
    },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: 'Reply with the word ok.' }],
      stream,
      max_completion_tokens: 8,
    }),
  });
  // Encrypt protocol-supported fields to the verified model key and set the E2EE
  // headers. Other fields stay unchanged. This step does not send the request.
  // Each preparation creates a fresh response key pair, held by decryptResponse.
  const prepared = await prepareE2eeChatRequest({
    request,
    modelKey,
  });

  // The signature covers the encrypted request/response bodies, not the plaintext
  // shown to the user. Save the exact outgoing bytes without reserializing them.
  const requestBytes = await prepared.request.clone().arrayBuffer();
  const requestBody = new Uint8Array(requestBytes);
  const response = await pinnedTlsFetch(prepared.request);
  if (!response.ok) {
    throw new Error(
      `Chat request failed (${response.status}): ${await response.text()}`,
    );
  }
  // Keep an encrypted copy for verification; decrypt the other branch for display.
  // For SSE, consume both branches concurrently so output remains streaming.
  const encryptedResponse = response.clone();
  const decryptedResponse = await prepared.decryptResponse(response);
  const [responseBytes, plaintextBody] = await Promise.all([
    encryptedResponse.arrayBuffer(),
    readDecryptedCompletion({ response: decryptedResponse, stream }),
  ]);

  return {
    id: readCompletionId({ responseText: plaintextBody, stream }),
    label: stream ? 'Streaming completion' : 'Completion',
    requestBody,
    responseBody: new Uint8Array(responseBytes),
  };
}

async function readDecryptedCompletion({
  response,
  stream,
}: ReadDecryptedCompletionParams): Promise<string> {
  if (!stream) {
    const responseText = await response.text();
    console.log(responseText);
    return responseText;
  }
  if (response.body === null) {
    throw new Error('Streaming Chat response has no body');
  }
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let responseText = '';
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      // Print raw decrypted SSE for this example; a UI would parse its data events.
      // Retain the text only to extract the completion ID, not for signature checks.
      process.stdout.write(chunk.value);
      responseText += chunk.value;
    }
  } finally {
    reader.releaseLock();
  }
  return responseText;
}

function createGatewayPinnedTlsFetch(
  tlsBinding: GatewayTlsBinding,
): typeof globalThis.fetch {
  if (tlsBinding.kind !== 'attested') {
    throw new Error('Expected TLS-bound Gateway evidence');
  }
  // Check each Chat connection against the attested SPKI. Reusing the original
  // attestation connection is unnecessary as long as the TLS key matches.
  return createPinnedTlsFetch(tlsBinding.spkiFingerprint);
}

async function verifyCompletionResponse({
  client,
  completion,
  gateway,
  model,
}: VerifyCompletionResponseParams): Promise<void> {
  // Retrieve the signature after the full response has been received. The ID is
  // only used for lookup; verification binds the saved bytes to an attested signer.
  const signature = await client.fetchCompletionSignature({
    completionId: completion.id,
    signingAlgo: SIGNING_ALGO,
  });

  if (signature.kind === 'provider_tee') {
    // Match the signature to the model selected for encryption, not another report.
    verifyModelResponse({
      requestBody: completion.requestBody,
      responseBody: completion.responseBody,
      signature,
      attestation: model,
    });
    console.log(`${completion.label}: verified model response signature.`);
  } else {
    // A Gateway signature authenticates the final bytes returned by the Gateway.
    // It does not prove model execution, even though model attestation passed above.
    verifyGatewayResponse({
      requestBody: completion.requestBody,
      responseBody: completion.responseBody,
      signature,
      attestation: gateway,
    });
    console.log(`${completion.label}: verified Gateway response signature.`);
  }
}

function readCompletionId({
  responseText,
  stream,
}: ReadCompletionIdParams): string {
  if (!stream) {
    return readJsonCompletionId(responseText);
  }

  for (const line of responseText.split(/\r\n|\n|\r/)) {
    if (!line.startsWith('data: ') || line === 'data: [DONE]') {
      continue;
    }
    try {
      return readJsonCompletionId(line.slice('data: '.length));
    } catch {
      // Later events may contain the completion ID.
    }
  }
  throw new Error('Streaming Chat response did not contain an id');
}

function readJsonCompletionId(text: string): string {
  const response: unknown = JSON.parse(text);
  if (
    typeof response !== 'object' ||
    response === null ||
    !('id' in response) ||
    typeof response.id !== 'string' ||
    response.id.length === 0
  ) {
    throw new Error('Chat response did not contain an id');
  }
  return response.id;
}

type Completion = {
  readonly id: string;
  readonly label: string;
  // Exact encrypted HTTP body bytes retained for response signature verification.
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
};

type CompletionExampleParams = {
  readonly apiKey: string;
  readonly pinnedTlsFetch: typeof globalThis.fetch;
  readonly modelKey: E2eeModelKey;
};

type SendCompletionParams = CompletionExampleParams & {
  readonly stream: boolean;
};

type ReadCompletionIdParams = {
  readonly responseText: string;
  readonly stream: boolean;
};

type ReadDecryptedCompletionParams = {
  readonly response: Response;
  readonly stream: boolean;
};

type VerifyCompletionResponseParams = {
  readonly client: AttestationClient;
  readonly completion: Completion;
  readonly gateway: VerifiedGatewayAttestation;
  readonly model: VerifiedModelAttestation;
};

type ModelAttestationWithPublicKey = VerifiedModelAttestation & {
  readonly signingPublicKey: string;
};
