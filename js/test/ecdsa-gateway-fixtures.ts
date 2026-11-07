import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ethers } from 'ethers';
import type { TdxQuoteVerificationResult } from '../src';
import {
  buildE2eeFieldAad,
  buildE2eeRequestAad,
  decryptE2eeText,
  encryptE2eeText,
} from '../src/core/e2ee';
import { appCompose, createGatewayTlsQuote } from './fixtures';

import { model } from './inference-client-fixtures';

const gatewayKey = new ethers.Wallet(
  '0x0123456789012345678901234567890123456789012345678901234567890123',
);
const modelKey = new ethers.Wallet(
  '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
);
export const modelPublicKey = modelKey.signingKey.publicKey.slice(4);
const eventLog = [
  {
    digest: '00'.repeat(48),
    imr: 3,
    event_type: 0,
    event: 'compose-hash',
    event_payload: 'beef',
  },
];

type EcdsaGatewayState = {
  readonly attestationAlgorithms: string[];
  readonly signatureAlgorithms: string[];
  readonly completionHeaders: Headers[];
  readonly decryptedPrompts: string[];
};

type StoredSignature = {
  readonly text: string;
  readonly signature: string;
  readonly kind: 'gateway' | 'provider_tee';
  readonly signer: ethers.Wallet;
};

type CreateEcdsaGatewayParams = {
  readonly signatureKind?: StoredSignature['kind'];
  readonly modelReportCount?: number;
};

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { 'content-type': 'application/json' },
  });
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function quoteForSigner({
  nonce,
  signerAddress,
}: {
  readonly nonce: string;
  readonly signerAddress: string;
}): TdxQuoteVerificationResult {
  const signerBinding = Buffer.alloc(32);
  Buffer.from(signerAddress.slice(2), 'hex').copy(signerBinding);
  return createGatewayTlsQuote({
    reportData: Buffer.concat([signerBinding, Buffer.from(nonce, 'hex')]),
  });
}

export function createEcdsaGateway({
  signatureKind = 'provider_tee',
  modelReportCount = 1,
}: CreateEcdsaGatewayParams = {}): {
  readonly fetch: typeof globalThis.fetch;
  readonly tdxQuoteVerifier: (quote: string) => TdxQuoteVerificationResult;
  readonly state: EcdsaGatewayState;
} {
  const quotes = new Map<string, TdxQuoteVerificationResult>();
  const signatures = new Map<string, StoredSignature>();
  const state: EcdsaGatewayState = {
    attestationAlgorithms: [],
    signatureAlgorithms: [],
    completionHeaders: [],
    decryptedPrompts: [],
  };

  function createAttestation({
    nonce,
    signer,
    includeModelKey,
    replica = 0,
  }: {
    readonly nonce: string;
    readonly signer: ethers.Wallet;
    readonly includeModelKey: boolean;
    readonly replica?: number;
  }): Record<string, unknown> {
    const quoteId = `${signer.address}:${nonce}:${replica}`;
    const quote = quoteForSigner({ nonce, signerAddress: signer.address });
    quotes.set(quoteId, quote);
    return {
      request_nonce: nonce,
      signing_algo: 'ecdsa',
      signing_address: signer.address,
      ...(includeModelKey ? { signing_public_key: modelPublicKey } : {}),
      intel_quote: quoteId,
      event_log: eventLog,
      info: { tcb_info: { app_compose: appCompose } },
      report_data: Buffer.from(quote.reportData).toString('hex'),
    };
  }

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (url.pathname === `/v1/model/${encodeURIComponent(model)}`) {
      expect(request.method).toBe('GET');
      return jsonResponse({
        metadata: { providerType: 'vllm', attestationSupported: true },
      });
    }

    if (url.pathname === '/v1/attestation/report') {
      const nonce = url.searchParams.get('nonce');
      if (nonce === null) {
        throw new Error('Expected an attestation nonce');
      }
      state.attestationAlgorithms.push(
        url.searchParams.get('signing_algo') ?? '',
      );
      if (url.searchParams.has('model')) {
        return jsonResponse({
          model_attestations: Array.from(
            { length: modelReportCount },
            (_, replica) =>
              createAttestation({
                nonce,
                signer: modelKey,
                includeModelKey: true,
                replica,
              }),
          ),
        });
      }
      return jsonResponse({
        gateway_attestation: createAttestation({
          nonce,
          signer: gatewayKey,
          includeModelKey: false,
        }),
      });
    }

    if (url.pathname.startsWith('/v1/signature/')) {
      state.signatureAlgorithms.push(
        url.searchParams.get('signing_algo') ?? '',
      );
      const completionId = url.pathname.slice('/v1/signature/'.length);
      const signature = signatures.get(completionId);
      if (signature === undefined) {
        throw new Error(`Missing signature for ${completionId}`);
      }
      return jsonResponse({
        signature_kind: signature.kind,
        text: signature.text,
        signature: signature.signature,
        signing_algo: 'ecdsa',
        signing_address: signature.signer.address,
      });
    }

    if (url.pathname === '/v1/systemone') {
      state.completionHeaders.push(request.headers);
      const requestBody = new Uint8Array(await request.arrayBuffer());
      const response = jsonResponse({
        model,
        answers: { billing: { type: 'noul', noul: 0.9 } },
        usage: { input_tokens: 10, output_tokens: 2 },
      });
      response.headers.set('x-generation-id', 'decision-ecdsa');
      const responseBody = new Uint8Array(await response.clone().arrayBuffer());
      const text = `${signatureKind === 'provider_tee' ? `${model}:` : ''}${sha256(requestBody)}:${sha256(responseBody)}`;
      const signer = signatureKind === 'provider_tee' ? modelKey : gatewayKey;
      signatures.set('decision-ecdsa', {
        text,
        signature: await signer.signMessage(text),
        kind: signatureKind,
        signer,
      });
      return response;
    }

    if (url.pathname === '/v1/messages' || url.pathname === '/v1/responses') {
      const requestBody = new Uint8Array(await request.arrayBuffer());
      const { stream } = JSON.parse(new TextDecoder().decode(requestBody));
      const messages = url.pathname.endsWith('/messages');
      const endpoint = messages ? 'messages' : 'responses';
      const file = messages ? 'message' : 'response';
      const responseBody = readFileSync(
        resolve(
          __dirname,
          `../../test-fixtures/${endpoint}/${file}.${stream ? 'sse' : 'json'}`,
        ),
      );
      const text = `${sha256(requestBody)}:${sha256(responseBody)}`;
      signatures.set(messages ? 'msg_fixture' : 'resp_fixture', {
        text,
        signature: await gatewayKey.signMessage(text),
        kind: 'gateway',
        signer: gatewayKey,
      });
      return new Response(responseBody, {
        headers: {
          'content-type': stream ? 'text/event-stream' : 'application/json',
        },
      });
    }

    if (url.pathname !== '/v1/chat/completions') {
      throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
    }

    state.completionHeaders.push(request.headers);
    const clientPublicKey = request.headers.get('x-client-pub-key');
    const requestBody = new Uint8Array(await request.clone().arrayBuffer());
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as {
      messages: Array<{ content: string }>;
      stream?: boolean;
    };
    state.decryptedPrompts.push(
      clientPublicKey === null
        ? body.messages[0].content
        : decryptE2eeText({
            ciphertext: body.messages[0]?.content ?? '',
            clientKeyPair: {
              signingAlgo: 'ecdsa',
              publicKey: modelPublicKey,
              privateKey: modelKey.privateKey,
            },
            field: 'messages[0].content',
            associatedData: buildE2eeFieldAad(
              buildE2eeRequestAad({
                signingAlgo: 'ecdsa',
                publicKey: clientPublicKey,
              }),
              'messages[].content',
            ),
          }),
    );
    const content =
      clientPublicKey === null
        ? 'private ECDSA response'
        : encryptE2eeText({
            plaintext: 'private ECDSA response',
            modelKey: { signingAlgo: 'ecdsa', publicKey: clientPublicKey },
          });
    const value = {
      id: 'chatcmpl-ecdsa',
      choices: [
        {
          [body.stream ? 'delta' : 'message']: { role: 'assistant', content },
          finish_reason: 'stop',
        },
      ],
    };
    const response = body.stream
      ? new Response(`data: ${JSON.stringify(value)}\n\ndata: [DONE]\n\n`, {
          headers: { 'content-type': 'text/event-stream' },
        })
      : jsonResponse(value);
    const responseBody = new Uint8Array(await response.clone().arrayBuffer());
    const signedText =
      signatureKind === 'provider_tee'
        ? `${model}:${sha256(requestBody)}:${sha256(responseBody)}`
        : `${sha256(requestBody)}:${sha256(responseBody)}`;
    const signer = signatureKind === 'provider_tee' ? modelKey : gatewayKey;
    signatures.set('chatcmpl-ecdsa', {
      text: signedText,
      signature: await signer.signMessage(signedText),
      kind: signatureKind,
      signer,
    });
    return response;
  };

  return {
    fetch,
    tdxQuoteVerifier(quote: string): TdxQuoteVerificationResult {
      const result = quotes.get(quote);
      if (result === undefined) {
        throw new Error(`Unknown quote: ${quote}`);
      }
      return result;
    },
    state,
  };
}
