import Anthropic from "@anthropic-ai/sdk";
import { InferenceClient } from "@nearai/inference-sdk/node";

const BASE_URL = process.env.NEARAI_BASE_URL ?? "https://cloud-api.near.ai/v1/";
const MODEL = process.env.NEARAI_MODEL ?? "anthropic/claude-haiku-4-5";

async function main(): Promise<void> {
	const apiKey = process.env.NEARAI_API_KEY;
	if (!apiKey) throw new Error("NEARAI_API_KEY is required");
	const inference = new InferenceClient({
		apiKey,
		baseUrl: BASE_URL,
		ohttp: process.env.NEARAI_OHTTP === "true",
	});
	const anthropic = new Anthropic({
		apiKey,
		// The official SDK appends /v1/messages to this API root.
		baseURL: inference.getBaseUrl().replace(/v1\/$/, ""),
		fetch: inference.fetch,
		maxRetries: 0,
	});
	const request: Anthropic.MessageCreateParamsNonStreaming = {
		model: MODEL,
		max_tokens: 128,
		messages: [{ role: "user", content: "Reply with the word ok." }],
	};
	const message = await anthropic.messages.create(request);
	const receipt = await inference.verifyResponse(message.id);
	console.log({
		stream: false,
		content: message.content,
		signatureKind: receipt.signatureKind,
	});

	const stream = await anthropic.messages.create({ ...request, stream: true });
	let responseId: string | undefined;
	let text = "";
	// Retain streamed text until the complete response has been verified.
	for await (const event of stream) {
		if (event.type === "message_start") responseId = event.message.id;
		if (
			event.type === "content_block_delta" &&
			event.delta.type === "text_delta"
		)
			text += event.delta.text;
	}
	if (responseId === undefined) throw new Error("Stream returned no message ID");
	const streamReceipt = await inference.verifyResponse(responseId);
	console.log({ stream: true, text, signatureKind: streamReceipt.signatureKind });
}

await main();
