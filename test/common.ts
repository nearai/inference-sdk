import { ChatSignature, AttestationReport } from '../src';
import {
  ChatCompletionsParams,
  ChatCompletionsResponse,
} from './types';

export async function fetchAttestationReport(
  apiUrl: string,
  apiKey: string,
  model: string,
  requestNonce: string
): Promise<AttestationReport> {
  const res = await fetch(
    `${apiUrl}/attestation/report?model=${encodeURIComponent(model)}&nonce=${requestNonce}`, {
      method: 'GET',
      headers: {
        'authorization': `Bearer ${apiKey}`,
      }
  });

  if (!res.ok) {
    throw Error(`Failed to fetch attestation report with status code: ${res.status}`);
  }

  return res.json();
}

export async function fetchChatSignature(
  apiUrl: string,
  apiKey: string,
  chatId: string,
  model: string,
  signingAlgo: string
): Promise<ChatSignature> {
  const res = await fetch(
  `${apiUrl}/signature/${chatId}?model=${encodeURIComponent(model)}&signing_algo=${encodeURIComponent(signingAlgo)}`, {
    method: 'GET',
    headers: {
      'authorization': `Bearer ${apiKey}`,
    }
  });

  if (!res.ok) {
    throw Error(`Failed to fetch signature with status code: ${res.status}`);
  }

  return res.json();
}

export async function chatCompletions({
  apiUrl,
  apiKey,
  requestBody,
}: ChatCompletionsParams): Promise<ChatCompletionsResponse> {
  const requestBodyRaw = Buffer.from(JSON.stringify(requestBody));

  const res = await fetch(
   `${apiUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${apiKey}`,
    },
    body: requestBodyRaw,
  });

  if (!res.ok) {
    throw Error(`Failed to chat with status code: ${res.status}`);
  }

  const responseBodyRaw = Buffer.from(await res.arrayBuffer());
  const responseBody = JSON.parse(responseBodyRaw.toString());

  return {
    requestBodyRaw,
    responseBodyRaw,
    responseBody,
  }
}
