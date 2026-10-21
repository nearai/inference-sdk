import { InferenceClient } from '@nearai/inference-sdk/node';

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) throw new Error('NEARAI_API_KEY is required');
const client = new InferenceClient({ apiKey });
const request = { model: 'z-ai/glm-5.3-flash', input: 'Reply with the word ok.', store: false };
const response = await client.responses.create(request);
await client.verifyResponse(response.id);
console.log(response.output_text);

const stream = await client.responses.create({ ...request, stream: true });
let responseId: string | undefined;
for await (const event of stream) {
  if (event.type === 'response.created') responseId = event.response.id;
  if (event.type === 'response.output_text.delta') process.stdout.write(event.delta);
}
if (responseId === undefined) throw new Error('Stream returned no response ID');
// Streamed text is provisional until the complete response is verified.
await client.verifyResponse(responseId);
console.log('\nVerified Gateway Responses receipt.');
