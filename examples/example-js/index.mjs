import {
	AttestationClient,
	verifyGatewayAttestation,
	verifyGatewayResponse,
	verifyModelAttestation,
	verifyModelResponse,
} from "verifiable-ai-sdk/node";

const API_URL = "https://cloud-api.near.ai/v1/chat/completions";
const MODEL = "z-ai/glm-5.2";
const SIGNING_ALGO = "ecdsa";
const decoder = new TextDecoder();

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) {
	throw new Error("NEARAI_API_KEY is required");
}

const client = new AttestationClient({ apiKey });

// Verify both deployments before sending either completion. These verified
// results are later paired with the completion receipt according to its kind.
const verifiedGatewayAttestation = await verifyGatewayDeployment();
const verifiedModelAttestation = await verifyModelDeployment();

await verifyCompletion({
	stream: false,
	verifiedGatewayAttestation,
	verifiedModelAttestation,
});
await verifyCompletion({
	stream: true,
	verifiedGatewayAttestation,
	verifiedModelAttestation,
});

async function verifyGatewayDeployment() {
	const fetched = await client.fetchGatewayAttestation({
		signingAlgo: SIGNING_ALGO,
	});
	const verified = await verifyGatewayAttestation({
		attestation: fetched.attestation,
		clientBinding: fetched.clientBinding,
	});
	console.log("Gateway deployment: verified.");
	return verified;
}

async function verifyModelDeployment() {
	const fetched = await client.fetchModelAttestations({
		model: MODEL,
		signingAlgo: SIGNING_ALGO,
	});
	const [attestation] = fetched.attestations;
	if (!attestation) {
		throw new Error("Cloud API returned no model attestation");
	}
	const verified = await verifyModelAttestation({
		attestation,
		clientBinding: fetched.clientBinding,
	});
	console.log("Model deployment: verified.");
	return verified;
}

async function verifyCompletion({
	stream,
	verifiedGatewayAttestation,
	verifiedModelAttestation,
}) {
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
	const signature = await client.fetchCompletionSignature({
		completionId,
		signingAlgo: SIGNING_ALGO,
	});

	if (signature.kind === "provider_tee") {
		verifyModelResponse({
			requestBody,
			responseBody,
			signature,
			attestation: verifiedModelAttestation,
		});
		console.log(`${label}: verified a model-serving TEE signature.`);
		return;
	}

	verifyGatewayResponse({
		requestBody,
		responseBody,
		signature,
		attestation: verifiedGatewayAttestation,
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
