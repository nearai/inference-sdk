import {
  InferenceClient,
  verifyDeploymentImageProvenance,
  type ImageProvenancePolicy,
} from '@nearai/inference-sdk/node';

const BASE_URL = 'https://cloud-api.near.ai/v1/';
const MODEL = 'z-ai/glm-5.3-flash';
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

  const inferenceClient = new InferenceClient({
    apiKey,
    baseUrl: BASE_URL,
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
  // before Chat is sent. E2EE and Gateway TLS verification stay enabled.
  // Successful attestations are cached for 60 minutes.
  // Model runtime images require direct Compose Manager evidence, which this
  // Gateway-based SDK does not retrieve. A launcher check is not a substitute.
  const completion = await inferenceClient.chat.completions.create({
    model: MODEL,
    messages: [{ role: 'user', content: 'Reply with the word ok.' }],
    max_completion_tokens: 8,
  });

  const verified = await inferenceClient.verifyResponse(completion.id);
  console.log(completion.choices[0]?.message.content ?? '');
  console.log(`Verified ${verified.signatureKind} response.`);
}

await main();
