import type {
  E2eeModelKey,
  GatewayTlsBinding,
  SigningAlgo,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from '@nearai/inference-sdk/node';
import {
  AttestationClient,
  createPinnedTlsFetch,
  findModelAttestationsForSignature,
  prepareE2eeChatRequest,
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '@nearai/inference-sdk/node';
import { readChatOutput } from '../utils/chat-output.ts';

// This example composes the SDK's standalone APIs: verify attestations, encrypt
// and send Chat requests, decrypt responses, then verify their signatures.
const API_KEY = process.env.NEARAI_API_KEY;
const BASE_URL = `${(
  process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1/'
).replace(/\/+$/, '')}/`;
const MODEL = process.env.NEARAI_MODEL ?? 'z-ai/glm-5.3-flash';
const SIGNING_ALGO = (process.env.NEARAI_SIGNING_ALGO ??
  'ed25519') as SigningAlgo;

await main();

async function main(): Promise<void> {
  if (!API_KEY) {
    throw new Error('NEARAI_API_KEY is required');
  }

  const bootstrapClient = new AttestationClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
  });

  // Verify the Gateway and every returned model report before sending a prompt.
  // A failed check throws and stops this flow before either Chat request.
  const gateway = await fetchAndVerifyGateway(bootstrapClient);
  const pinnedTlsFetch = createGatewayPinnedTlsFetch(gateway.tlsBinding);
  const attestationClient = new AttestationClient({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
    fetch: pinnedTlsFetch,
  });
  const modelAttestations =
    await fetchAndVerifyModelAttestations(attestationClient);

  // Encryption needs only the verified public key and its algorithm. Keep the
  // full model verification result separately for the response signature check.
  const selectedModelAttestation =
    findModelAttestationForEncryption(modelAttestations);
  const modelKey: E2eeModelKey = {
    signingAlgo: selectedModelAttestation.signer.signingAlgo,
    publicKey: selectedModelAttestation.signingPublicKey,
  };

  // Non-streaming: decrypt the JSON response, verify its signature, then display it.
  const nonStreamingCompletion = await sendCompletion({
    apiKey: API_KEY,
    stream: false,
    pinnedTlsFetch,
    modelKey,
  });
  await verifyResponse({
    client: attestationClient,
    completion: nonStreamingCompletion,
    gateway,
    modelAttestations,
    selectedModelAttestation,
  });

  // Streaming: display decrypted SSE as it arrives. Signature verification needs
  // the complete response bytes, so it runs after the stream finishes.
  const streamingCompletion = await sendCompletion({
    apiKey: API_KEY,
    stream: true,
    pinnedTlsFetch,
    modelKey,
  });
  await verifyResponse({
    client: attestationClient,
    completion: streamingCompletion,
    gateway,
    modelAttestations,
    selectedModelAttestation,
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
  const verified = await verifyGatewayAttestation({
    attestation: fetched.attestation,
    clientBinding: fetched.clientBinding,
  });
  console.log('Gateway attestation verified.');
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
  console.log(`Verified ${verified.length} model attestations.`);
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
      max_completion_tokens: 1024,
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
  // Consume both branches before verifying and displaying the output.
  const encryptedResponse = response.clone();
  const decryptedResponse = await prepared.decryptResponse(response);
  const [responseBytes, output] = await Promise.all([
    encryptedResponse.arrayBuffer(),
    readChatOutput(decryptedResponse, stream),
  ]);

  return {
    id: output.id,
    label: stream ? 'Streaming completion' : 'Completion',
    requestBody,
    responseBody: new Uint8Array(responseBytes),
    text: output.text,
  };
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

async function verifyResponse({
  client,
  completion,
  gateway,
  modelAttestations,
  selectedModelAttestation,
}: VerifyResponseParams): Promise<void> {
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
      attestation: selectedModelAttestation,
    });
    const matchingAttestations = findModelAttestationsForSignature({
      attestations: modelAttestations,
      signature,
    });
    console.log(
      `${completion.label}: verified model response signature (${matchingAttestations.length} matching reports).`,
    );
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
  if (completion.text !== undefined) console.log(completion.text);
}

type Completion = {
  readonly id: string;
  readonly label: string;
  // Exact encrypted HTTP body bytes retained for response signature verification.
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly text?: string;
};

type SendCompletionParams = {
  readonly stream: boolean;
  readonly apiKey: string;
  readonly pinnedTlsFetch: typeof globalThis.fetch;
  readonly modelKey: E2eeModelKey;
};

type VerifyResponseParams = {
  readonly client: AttestationClient;
  readonly completion: Completion;
  readonly gateway: VerifiedGatewayAttestation;
  readonly modelAttestations: readonly VerifiedModelAttestation[];
  readonly selectedModelAttestation: VerifiedModelAttestation;
};

type ModelAttestationWithPublicKey = VerifiedModelAttestation & {
  readonly signingPublicKey: string;
};
