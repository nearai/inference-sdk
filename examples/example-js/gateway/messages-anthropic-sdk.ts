import Anthropic from "@anthropic-ai/sdk";
import { InferenceClient } from "@nearai/inference-sdk/node";

const BASE_URL = "https://cloud-api.near.ai";
const MODEL = "anthropic/claude-haiku-4-5";

async function main(): Promise<void> {
	const apiKey = process.env.NEARAI_API_KEY;
	if (!apiKey) throw new Error("NEARAI_API_KEY is required");
	const inference = new InferenceClient({ apiKey, baseUrl: `${BASE_URL}/v1/` });
	const anthropic = new Anthropic({
		apiKey,
		baseURL: BASE_URL,
		fetch: inference.fetch,
		maxRetries: 0,
	});
	const message = await anthropic.messages.create({
		model: MODEL,
		max_tokens: 128,
		messages: [{ role: "user", content: "Reply with the word ok." }],
	});
	const receipt = await inference.verifyResponse(message.id);
	console.log({
		content: message.content,
		signatureKind: receipt.signatureKind,
	});
}

await main();
