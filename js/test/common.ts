import {
  ChatSignature,
  AttestationReport,
  SigningAlgo,
  DomainAttestation,
} from '../src';
import { ChatCompletionsParams, ChatCompletionsResponse } from './types';
import crypto from 'crypto';

export async function sleep(ms: number) {
  await new Promise<void>((resolve) => {
    setTimeout(() => resolve(), ms);
  });
}

export function generateRequestNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

export async function fetchAttestationReport({
  apiUrl,
  apiKey,
  params: { model, requestNonce, signingAlgo },
}: {
  apiUrl: string;
  apiKey: string;
  params: {
    model: string;
    requestNonce: string;
    signingAlgo: SigningAlgo;
  };
}): Promise<AttestationReport> {
  const res = await fetch(
    `${apiUrl}/attestation/report?model=${encodeURIComponent(model)}&nonce=${requestNonce}&signing_algo=${signingAlgo}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${apiKey}`,
      },
    },
  );

  if (!res.ok) {
    throw Error(
      `Failed to fetch attestation report with status code: ${res.status}`,
    );
  }

  return res.json();
}

export async function fetchChatSignature({
  apiUrl,
  apiKey,
  params: { chatId, model, signingAlgo },
}: {
  apiUrl: string;
  apiKey: string;
  params: {
    chatId: string;
    model: string;
    signingAlgo: SigningAlgo;
  };
}): Promise<ChatSignature> {
  const res = await fetch(
    `${apiUrl}/signature/${chatId}?model=${encodeURIComponent(model)}&signing_algo=${signingAlgo}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${apiKey}`,
      },
    },
  );

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

  const res = await fetch(`${apiUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
    },
    body: requestBodyRaw,
  });

  if (!res.ok) {
    throw Error(`Failed to chat with status code: ${res.status}`);
  }

  const responseBodyRaw = Buffer.from(await res.bytes());

  let id: string;

  if (requestBody.stream) {
    const lines = responseBodyRaw.toString().split('\n');
    const firstChunk = JSON.parse(lines[0].slice(6)); // data: {...
    id = firstChunk.id;
  } else {
    const data = JSON.parse(responseBodyRaw.toString());
    id = data.id;
  }

  return {
    id,
    requestBodyRaw,
    responseBodyRaw,
  };
}

export async function fetchDomainAttestation(
  domain: string,
): Promise<DomainAttestation> {
  const evidencesUrl = `https://${domain}/evidences/`;

  const intelQuoteUrl = `${evidencesUrl}quote.json`;
  const certUrl = `${evidencesUrl}cert-${domain}.pem`;
  const acmeAccountUrl = `${evidencesUrl}acme-account.json`;
  const sha256sumUrl = `${evidencesUrl}sha256sum.txt`;
  const infoUrl = `${evidencesUrl}info.json`;

  const [intelQuoteRes, certRes, acmeAccountRes, sha256sumRes, infoRes] =
    await Promise.all([
      fetch(intelQuoteUrl),
      fetch(certUrl),
      fetch(acmeAccountUrl),
      fetch(sha256sumUrl),
      fetch(infoUrl),
    ]);

  if (!intelQuoteRes.ok) {
    throw Error(
      `Failed to fetch Intel quote with status code: ${intelQuoteRes.status}`,
    );
  }

  if (!certRes.ok) {
    throw Error(
      `Failed to fetch certificate with status code: ${certRes.status}`,
    );
  }

  if (!acmeAccountRes.ok) {
    throw Error(
      `Failed to fetch ACME account with status code: ${acmeAccountRes.status}`,
    );
  }

  if (!sha256sumRes.ok) {
    throw Error(
      `Failed to fetch sha256 sum with status code: ${sha256sumRes.status}`,
    );
  }

  if (!infoRes.ok) {
    throw Error(`Failed to fetch info with status code: ${infoRes.status}`);
  }

  return {
    intel_quote: (await intelQuoteRes.json()).quote,
    domain,
    cert: await certRes.text(),
    acmeAccount: await acmeAccountRes.text(),
    sha256sum: await sha256sumRes.text(),
    info: await infoRes.json(),
  };
}
