import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import Anthropic from '@anthropic-ai/sdk';
import { ethers } from 'ethers';
import OpenAI from 'openai';
import { InferenceClient, type TdxQuoteVerificationResult } from '../src';
import {
  buildE2eeFieldAad,
  buildE2eeRequestAad,
  decryptE2eeText,
  encryptE2eeText,
} from '../src/core/e2ee';
import { appCompose, createGatewayTlsQuote } from './fixtures';

const baseUrl = 'https://gateway.test/v1/';
const model = 'glm-5.3-flash';
const gatewayKey = new ethers.Wallet(
  '0x0123456789012345678901234567890123456789012345678901234567890123',
);
const modelKey = new ethers.Wallet(
  '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
);
const modelPublicKey = modelKey.signingKey.publicKey.slice(4);
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

function createEcdsaGateway({
  signatureKind = 'provider_tee',
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
  }: {
    readonly nonce: string;
    readonly signer: ethers.Wallet;
    readonly includeModelKey: boolean;
  }): Record<string, unknown> {
    const quoteId = `${signer.address}:${nonce}`;
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
          model_attestations: [
            createAttestation({
              nonce,
              signer: modelKey,
              includeModelKey: true,
            }),
          ],
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
    if (clientPublicKey === null) {
      throw new Error('Expected an E2EE client key');
    }
    const requestBody = new Uint8Array(await request.clone().arrayBuffer());
    const body = JSON.parse(new TextDecoder().decode(requestBody)) as {
      messages: Array<{ content: string }>;
    };
    state.decryptedPrompts.push(
      decryptE2eeText({
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
    const response = jsonResponse({
      id: 'chatcmpl-ecdsa',
      choices: [
        {
          message: {
            role: 'assistant',
            content: encryptE2eeText({
              plaintext: 'private ECDSA response',
              modelKey: {
                signingAlgo: 'ecdsa',
                publicKey: clientPublicKey,
              },
            }),
          },
        },
      ],
    });
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

describe('ECDSA inference client', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('verifies, encrypts, decrypts, and verifies a response signature with ECDSA', async () => {
    const gateway = createEcdsaGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      baseUrl,
      headers: { authorization: 'Bearer test-token' },
      signingAlgo: 'ecdsa',
      e2ee: true,
      gatewayVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
      },
      modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    });

    const response = await client.fetch(`${baseUrl}chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'private ECDSA request' }],
      }),
    });

    await expect(response.json()).resolves.toMatchObject({
      choices: [{ message: { content: 'private ECDSA response' } }],
    });
    await expect(
      client.verifyResponse('chatcmpl-ecdsa'),
    ).resolves.toMatchObject({
      id: 'chatcmpl-ecdsa',
      signatureKind: 'provider_tee',
    });

    expect(gateway.state.decryptedPrompts).toEqual(['private ECDSA request']);
    expect(gateway.state.attestationAlgorithms).toEqual(['ecdsa', 'ecdsa']);
    expect(gateway.state.signatureAlgorithms).toEqual(['ecdsa']);
    expect(gateway.state.completionHeaders).toHaveLength(1);
    const headers = gateway.state.completionHeaders[0];
    expect(headers.get('x-signing-algo')).toBe('ecdsa');
    expect(headers.get('x-client-pub-key')).toHaveLength(128);
    expect(headers.get('x-model-pub-key')).toBe(modelPublicKey);
    expect(headers.get('x-encryption-version')).toBe('3');
    expect(headers.get('x-encrypt-all-fields')).toBe('true');
  });

  test('verifies an ECDSA Gateway signature when the Gateway signs the response', async () => {
    const gateway = createEcdsaGateway({ signatureKind: 'gateway' });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      baseUrl,
      headers: { authorization: 'Bearer test-token' },
      signingAlgo: 'ecdsa',
      e2ee: true,
      gatewayVerification: {
        verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
      },
      modelVerification: { verifiers: { tdxQuote: gateway.tdxQuoteVerifier } },
    });

    const response = await client.fetch(`${baseUrl}chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'private ECDSA request' }],
      }),
    });

    await response.text();
    await expect(
      client.verifyResponse('chatcmpl-ecdsa'),
    ).resolves.toMatchObject({
      id: 'chatcmpl-ecdsa',
      signatureKind: 'gateway',
    });
  });

  test.each(['gateway', 'provider_tee'] as const)(
    'verifies System One %s receipts with ECDSA',
    async (signatureKind) => {
      const gateway = createEcdsaGateway({ signatureKind });
      jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
      const client = new InferenceClient({
        baseUrl,
        apiKey: 'test-token',
        signingAlgo: 'ecdsa',
        e2ee: false,
        gatewayVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
        modelVerification: {
          verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
        },
      });
      const result = await client.systemone.create({
        model,
        state: 'Charged twice',
        questions: {
          billing: { type: 'noul', instructions: 'Is this about billing?' },
        },
      });
      await expect(
        client.verifyResponse(result.decisionId),
      ).resolves.toMatchObject({ signatureKind });
      expect(gateway.state.attestationAlgorithms).toEqual(['ecdsa', 'ecdsa']);
      expect(gateway.state.signatureAlgorithms).toEqual(['ecdsa']);
      expect(gateway.state.completionHeaders[0].get('x-model-pub-key')).toBe(
        modelPublicKey,
      );
      expect(
        gateway.state.completionHeaders[0].get('x-signing-algo'),
      ).toBeNull();
    },
  );
});

describe('ECDSA Gateway endpoint adapters', () => {
  afterEach(() => jest.restoreAllMocks());
  for (const endpoint of ['messages', 'responses'] as const) {
    for (const official of [false, true]) {
      for (const stream of [false, true] as const) {
        test(`ECDSA ${endpoint}, official=${official}, stream=${stream}`, async () => {
          const gateway = createEcdsaGateway({ signatureKind: 'gateway' });
          const fetchSpy = jest
            .spyOn(globalThis, 'fetch')
            .mockImplementation(gateway.fetch);
          const client = new InferenceClient({
            apiKey: 'key',
            baseUrl,
            signingAlgo: 'ecdsa',
            gatewayVerification: {
              verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
            },
            modelVerification: {
              verifiers: { tdxQuote: gateway.tdxQuoteVerifier },
            },
          });
          const id = endpoint === 'messages' ? 'msg_fixture' : 'resp_fixture';
          if (endpoint === 'messages') {
            const api = official
              ? new Anthropic({
                  apiKey: 'key',
                  baseURL: 'https://gateway.test',
                  fetch: client.fetch,
                  maxRetries: 0,
                })
              : client;
            const result = await api.messages.create({
              model,
              max_tokens: 128,
              messages: [{ role: 'user', content: 'Hello' }],
              stream,
            });
            if (Symbol.asyncIterator in result) {
              let text = '';
              for await (const event of result) {
                if (event.type === 'message_start')
                  expect(event.message.id).toBe(id);
                if (
                  event.type === 'content_block_delta' &&
                  event.delta.type === 'text_delta'
                )
                  text += event.delta.text;
              }
              expect(text).toContain('Hello');
            } else expect(result.id).toBe(id);
          } else {
            const api = official
              ? new OpenAI({
                  apiKey: 'key',
                  baseURL: baseUrl,
                  fetch: client.fetch,
                  maxRetries: 0,
                })
              : client;
            const result = await api.responses.create({
              model,
              input: 'Hello',
              store: false,
              stream,
            });
            if (Symbol.asyncIterator in result) {
              let text = '';
              for await (const event of result) {
                if (event.type === 'response.created')
                  expect(event.response.id).toBe(id);
                if (event.type === 'response.output_text.delta')
                  text += event.delta;
              }
              expect(text).toContain('你好');
            } else expect(result.id).toBe(id);
          }
          const receipt = await client.verifyResponse(id);
          expect(receipt.signatureKind).toBe('gateway');
          expect(receipt.signature.signer.signingAlgo).toBe('ecdsa');
          fetchSpy.mockRestore();
        });
      }
    }
  }
});
