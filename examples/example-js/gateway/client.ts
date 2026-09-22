import {
  InferenceClient,
  verifyDeploymentImageProvenance,
  type ImageProvenancePolicy,
} from '@nearai/inference-sdk/node';

const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';
// Selects the algorithm for attestation, E2EE, and response signatures.
const SIGNING_ALGO = 'ed25519';

// Required Gateway images and build workflows. Add a reviewed `commit`
// to each policy if your application also requires commit pinning.
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

async function main(): Promise<void> {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('NEARAI_API_KEY is required');

  // Opt into NEAR model E2EE; Gateway TLS verification is enabled by default.
  // Attestations are reused for 60 minutes. Response records have a separate
  // 60-minute TTL, starting when the response finishes.
  const inferenceClient = new InferenceClient({
    apiKey,
    baseUrl: BASE_URL,
    signingAlgo: SIGNING_ALGO,
    e2ee: true,
    gatewayVerification: {
      verifiers: {
        deployment: ({ appCompose }) =>
          verifyDeploymentImageProvenance({
            appCompose,
            imagePolicies: GATEWAY_IMAGE_POLICIES,
          }),
      },
    },
  });

  // Gateway/model attestations and all four Gateway image checks must pass
  // before Chat is sent. These policies do not verify model runtime images.
  await runNonStreamingExample(inferenceClient);
  await runStreamingExample(inferenceClient);
}

async function runNonStreamingExample(
  inferenceClient: InferenceClient,
): Promise<void> {
  const completion = await inferenceClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 8,
  });
  console.log(completion.choices[0]?.message.content ?? '');

  const verified = await inferenceClient.verifyResponse(completion.id);
  console.log(`Verified ${verified.signatureKind} response.`);
}

async function runStreamingExample(
  inferenceClient: InferenceClient,
): Promise<void> {
  const stream = await inferenceClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 8,
    stream: true,
  });

  let completionId: string | undefined;
  for await (const chunk of stream) {
    completionId = chunk.id;
    process.stdout.write(chunk.choices[0]?.delta.content ?? '');
  }
  process.stdout.write('\n');

  // Consume the full stream before verifying its exact bytes.
  if (completionId === undefined)
    throw new Error('Stream returned no completion ID');
  const verified = await inferenceClient.verifyResponse(completionId);
  console.log(`Verified ${verified.signatureKind} streaming response.`);
}

await main();
