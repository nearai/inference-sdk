import {
	AttestationClient,
	findModelAttestationForSignature,
	verifyGatewayAttestation,
	verifyGatewayResponse,
	verifyModelAttestation,
	verifyModelResponse,
} from "verifiable-ai-sdk/node";

const API_URL = "https://cloud-api.near.ai/v1/chat/completions";
const MODEL = "z-ai/glm-5.2";
const decoder = new TextDecoder();

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) {
	throw new Error("NEARAI_API_KEY is required");
}

const client = new AttestationClient({ apiKey });

await verifyCompletion(false);
await verifyCompletion(true);

async function verifyCompletion(stream) {
	const label = stream ? "Streaming" : "Non-streaming";
	const requestBody = new TextEncoder().encode(
		JSON.stringify({
			model: MODEL,
			messages: [{ role: "user", content: "Reply with the word ok." }],
			stream,
			max_tokens: 8,
		}),
	);
	const completionResponse = await fetch(API_URL, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${apiKey}`,
			"Content-Type": "application/json",
			"Accept-Encoding": "identity",
			"x-no-aliasing": "true",
		},
		body: requestBody,
	});
	const responseBody = new Uint8Array(await completionResponse.arrayBuffer());
	if (!completionResponse.ok) {
		throw new Error(
			`Completion request failed (${completionResponse.status}): ${decoder.decode(responseBody)}`,
		);
	}

	// Keep these original bytes unchanged for response-signature verification.
	const completionId = readCompletionId(responseBody, stream);
	const signature = await client.fetchCompletionSignature({ completionId });

	if (signature.kind === "provider_tee") {
		const fetched = await client.fetchModelAttestations({ model: MODEL });
		const attestation = findModelAttestationForSignature({
			attestations: fetched.attestations,
			signature,
		});
		const verifiedAttestation = await verifyModelAttestation({
			attestation,
			clientBinding: fetched.clientBinding,
		});
		verifyModelResponse({
			requestBody,
			responseBody,
			signature,
			attestation: verifiedAttestation,
		});
		console.log(`${label}: verified a model-serving TEE signature.`);
		return;
	}

	const fetched = await client.fetchGatewayAttestation({
		signingAlgo: signature.signer.signingAlgo,
	});
	const verifiedAttestation = await verifyGatewayAttestation({
		attestation: fetched.attestation,
		clientBinding: fetched.clientBinding,
	});
	verifyGatewayResponse({
		requestBody,
		responseBody,
		signature,
		attestation: verifiedAttestation,
	});
	console.log(`${label}: verified a Gateway signature.`);
}

function readCompletionId(responseBody, stream) {
	if (!stream) {
		const completion = JSON.parse(decoder.decode(responseBody));
		if (typeof completion.id === "string") {
			return completion.id;
		}
		throw new Error("Completion response did not contain an id");
	}

	for (const line of decoder.decode(responseBody).split(/\r?\n/)) {
		if (!line.startsWith("data: ") || line === "data: [DONE]") {
			continue;
		}
		try {
			const event = JSON.parse(line.slice("data: ".length));
			if (typeof event.id === "string") {
				return event.id;
			}
		} catch {
			// Only the event id is parsed; responseBody remains unchanged below.
		}
	}
	throw new Error("Streaming completion response did not contain an id");
}
