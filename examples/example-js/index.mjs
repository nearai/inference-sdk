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
const verifiedModelAttestations = await verifyModelDeployments();

const nonStreamingCompletion = await sendCompletion({ stream: false });
await verifyCompletionReceipt({
	completion: nonStreamingCompletion,
	verifiedGatewayAttestation,
	verifiedModelAttestations,
});
const streamingCompletion = await sendCompletion({ stream: true });
await verifyCompletionReceipt({
	completion: streamingCompletion,
	verifiedGatewayAttestation,
	verifiedModelAttestations,
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

async function verifyModelDeployments() {
	const fetched = await client.fetchModelAttestations({
		model: MODEL,
		signingAlgo: SIGNING_ALGO,
	});
	if (fetched.attestations.length === 0) {
		throw new Error("Cloud API returned no model attestations");
	}
	const preflight = [];
	for (const attestation of fetched.attestations) {
		preflight.push({
			attestation,
			verified: await verifyModelAttestation({
				attestation,
				clientBinding: fetched.clientBinding,
			}),
		});
	}
	console.log(`Model deployments: verified ${preflight.length}.`);
	return preflight;
}

async function sendCompletion({ stream }) {
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
	return { completionId, label, requestBody, responseBody };
}

async function verifyCompletionReceipt({
	completion,
	verifiedGatewayAttestation,
	verifiedModelAttestations,
}) {
	const signature = await client.fetchCompletionSignature({
		completionId: completion.completionId,
		signingAlgo: SIGNING_ALGO,
	});

	if (signature.kind === "provider_tee") {
		const verifiedModelAttestation = selectVerifiedModelAttestation(
			signature,
			verifiedModelAttestations,
		);
		verifyModelResponse({
			requestBody: completion.requestBody,
			responseBody: completion.responseBody,
			signature,
			attestation: verifiedModelAttestation,
		});
		console.log(`${completion.label}: verified a model-serving TEE signature.`);
		return;
	}

	verifyGatewayResponse({
		requestBody: completion.requestBody,
		responseBody: completion.responseBody,
		signature,
		attestation: verifiedGatewayAttestation,
	});
	console.log(`${completion.label}: verified a Gateway signature.`);
}

function selectVerifiedModelAttestation(signature, preflight) {
	const attestation = findModelAttestationForSignature({
		attestations: preflight.map(({ attestation }) => attestation),
		signature,
	});
	const selected = preflight.find(
		(candidate) => candidate.attestation === attestation,
	);
	if (!selected) {
		throw new Error("Selected model attestation was not preflight verified");
	}
	return selected.verified;
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
