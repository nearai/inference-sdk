import { Buffer } from 'node:buffer';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';
import OpenAI from 'openai';
import {
  DirectInferenceClient,
  type DirectInferenceClientOptions,
  type QuoteVerificationResult,
} from '../src';
import { decryptE2eeText, encryptE2eeText } from '../src/core/e2ee';
import * as nodeTls from '../src/node/attestation-client';
import { NodeDirectInferenceClient } from '../src/node/direct-inference-client';
import { createModelAttestation, createModelQuote, sha256 } from './fixtures';
import { createOhttpEndpoint } from './ohttp-fixtures';

const baseUrl = 'https://model.test/v1';
const model = 'test-model';
const prompt = 'hello model';
const answer = 'hello direct';
const composes = [
  JSON.stringify({ services: { model: { image: 'model:revision-a' } } }),
  JSON.stringify({ services: { model: { image: 'model:revision-b' } } }),
];
const messages = [{ role: 'user' as const, content: prompt }];
const spkiFingerprints = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];

type CreateDirectEndpointParams = {
  readonly invalidSecondQuote?: boolean;
  readonly alterResponseBytes?: boolean;
  readonly wrongSignatureKey?: boolean;
  readonly additionalSigner?: boolean;
  readonly otherSignerFirst?: boolean;
  readonly omitPublicKeyFor?: readonly number[];
};

type CreateAttestationParams = {
  readonly nonce: string;
  readonly index: number;
  readonly includeSpkiFingerprint: boolean;
};

type ChatRequest = {
  readonly model: string;
  readonly messages: readonly { readonly content: string }[];
  readonly stream?: boolean;
};

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { 'content-type': 'application/json' },
  });
}

function chatRequest(): Request {
  return new Request(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, messages }),
  });
}

/**
 * An in-memory provider with real Ed25519 signatures and E2EE. Only the quote
 * adapter is synthetic: the SDK still checks bindings, measurements and policy.
 */
function createDirectEndpoint({
  invalidSecondQuote = false,
  alterResponseBytes = false,
  wrongSignatureKey = false,
  additionalSigner = false,
  otherSignerFirst = false,
  omitPublicKeyFor = [],
}: CreateDirectEndpointParams = {}) {
  const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
  const otherKeyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 8));
  const publicKey = Buffer.from(keyPair.publicKey).toString('hex');
  const secretKey = ed2curve.convertSecretKey(keyPair.secretKey);
  if (secretKey === null) throw new Error('Invalid fixture encryption key');
  const signingKey = wrongSignatureKey ? otherKeyPair : keyPair;
  const appComposes =
    additionalSigner || otherSignerFirst
      ? [
          ...composes,
          JSON.stringify({ services: { model: { image: 'model:other-key' } } }),
        ]
      : composes;
  const quotes = new Map<string, QuoteVerificationResult>();
  const signatures = new Map<string, Record<string, string>>();
  const state = {
    attestationRequests: 0,
    completionRequests: 0,
    signatureRequests: 0,
    verifiedQuotes: [] as string[],
    requests: [] as { body: ChatRequest; headers: Headers }[],
    decryptedPrompts: [] as string[],
  };

  function attestation({
    nonce,
    index,
    includeSpkiFingerprint,
  }: CreateAttestationParams) {
    const attestedKey = index === 2 ? otherKeyPair : keyPair;
    const attestedPublicKey = Buffer.from(attestedKey.publicKey).toString(
      'hex',
    );
    const signerBinding = includeSpkiFingerprint
      ? sha256(
          Buffer.concat([
            attestedKey.publicKey,
            Buffer.from(spkiFingerprints[index], 'hex'),
          ]),
        )
      : attestedKey.publicKey;
    const quoteId = `${nonce}:${index}`;
    const quote = createModelQuote({
      reportData: Buffer.concat([signerBinding, Buffer.from(nonce, 'hex')]),
      mrConfigId: Buffer.concat([
        Buffer.from([1]),
        sha256(appComposes[index]),
        Buffer.alloc(15),
      ]),
      debugEnabled: invalidSecondQuote && index === 1,
    });
    quotes.set(quoteId, quote);
    return {
      model_name: model,
      request_nonce: nonce,
      signing_algo: 'ed25519',
      signing_address: attestedPublicKey,
      ...(omitPublicKeyFor.includes(index)
        ? {}
        : { signing_public_key: attestedPublicKey }),
      ...(includeSpkiFingerprint
        ? { tls_cert_fingerprint: spkiFingerprints[index] }
        : {}),
      intel_quote: quoteId,
      report_data: Buffer.from(quote.reportData).toString('hex'),
      event_log: createModelAttestation().eventLog,
      info: {
        instance_id: `instance-${index}`,
        tcb_info: { app_compose: appComposes[index] },
      },
    };
  }

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname === '/v1/attestation/report') {
      state.attestationRequests += 1;
      const nonce = url.searchParams.get('nonce');
      if (nonce === null) throw new Error('Missing attestation nonce');
      const includeSpkiFingerprint =
        url.searchParams.get('include_tls_fingerprint') === 'true';
      const attestations = appComposes.map((_, index) =>
        attestation({ nonce, index, includeSpkiFingerprint }),
      );
      return jsonResponse({
        ...attestations[0],
        all_attestations: otherSignerFirst
          ? [attestations[2], ...attestations.slice(0, 2)]
          : attestations,
      });
    }
    if (url.pathname.startsWith('/v1/signature/')) {
      state.signatureRequests += 1;
      const id = url.pathname.slice('/v1/signature/'.length);
      const signature = signatures.get(id);
      if (signature === undefined) throw new Error(`No signature for ${id}`);
      return jsonResponse(signature);
    }
    if (url.pathname !== '/v1/chat/completions') {
      throw new Error(`Unexpected endpoint: ${url.pathname}`);
    }

    state.completionRequests += 1;
    const requestBytes = Buffer.from(await request.arrayBuffer());
    const body = JSON.parse(requestBytes.toString('utf8')) as ChatRequest;
    state.requests.push({ body, headers: request.headers });
    const clientPublicKey = request.headers.get('x-client-pub-key');
    state.decryptedPrompts.push(
      clientPublicKey === null
        ? body.messages[0].content
        : decryptE2eeText({
            ciphertext: body.messages[0].content,
            clientKeyPair: {
              signingAlgo: 'ed25519',
              publicKey,
              x25519SecretKey: secretKey,
            },
            field: 'messages[0].content',
          }),
    );
    const content = (plaintext: string): string =>
      clientPublicKey === null
        ? plaintext
        : encryptE2eeText({
            plaintext,
            modelKey: { signingAlgo: 'ed25519', publicKey: clientPublicKey },
          });
    const id = `chatcmpl-direct-${state.completionRequests}`;
    const frames = body.stream
      ? ['hello ', 'direct']
          .map(
            (text, index) =>
              `data: ${JSON.stringify({
                id,
                object: 'chat.completion.chunk',
                created: 0,
                model,
                choices: [
                  {
                    index: 0,
                    delta: { content: content(text) },
                    finish_reason: index === 1 ? 'stop' : null,
                  },
                ],
              })}\n\n`,
          )
          .concat('data: [DONE]\n\n')
      : [
          JSON.stringify({
            id,
            object: 'chat.completion',
            created: 0,
            model,
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: content(answer) },
                finish_reason: 'stop',
              },
            ],
          }),
        ];
    const responseBytes = Buffer.from(frames.join(''));
    const text = `${model}:${sha256(requestBytes).toString('hex')}:${sha256(responseBytes).toString('hex')}`;
    signatures.set(id, {
      text,
      signature: Buffer.from(
        nacl.sign.detached(Buffer.from(text), signingKey.secretKey),
      ).toString('hex'),
      signing_address: Buffer.from(signingKey.publicKey).toString('hex'),
      signing_algo: 'ed25519',
    });
    // Whitespace changes signed bytes without making JSON or E2EE invalid.
    if (alterResponseBytes) frames.push('\n');
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          for (const frame of frames) controller.enqueue(Buffer.from(frame));
          controller.close();
        },
      }),
      {
        headers: {
          'content-type': body.stream
            ? 'text/event-stream'
            : 'application/json',
        },
      },
    );
  };

  jest.spyOn(globalThis, 'fetch').mockImplementation(fetch);
  const quoteVerifier = (quoteId: string): QuoteVerificationResult => {
    const quote = quotes.get(quoteId);
    if (quote === undefined) throw new Error('Unknown fixture quote');
    state.verifiedQuotes.push(quoteId);
    return quote;
  };
  const options: DirectInferenceClientOptions = {
    baseUrl,
    modelVerification: { verifiers: { quote: quoteVerifier } },
  };
  return { state, options, publicKey, fetch };
}

describe('DirectInferenceClient', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test.each([true, false])(
    'round-trips OHTTP JSON and SSE with byte-exact receipts and E2EE set to %s',
    async (e2ee) => {
      const provider = createDirectEndpoint({ otherSignerFirst: true });
      const endpoint = await createOhttpEndpoint({
        fetch: provider.fetch,
        signingKey: nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7)),
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(endpoint.fetch);
      const client = new DirectInferenceClient({
        ...provider.options,
        apiKey: 'direct-test-key',
        headers: { 'x-proxy-token': 'proxy-test-token' },
        ohttp: true,
        signingAlgo: 'ed25519',
        e2ee,
      });
      const completion = await client.chat.completions.create({
        model,
        messages,
      });
      expect(completion.choices[0].message.content).toBe(answer);
      await expect(client.verifyResponse(completion.id)).resolves.toMatchObject(
        {
          completionId: completion.id,
          signatureKind: 'provider_tee',
        },
      );

      const stream = await client.chat.completions.create({
        model,
        messages,
        stream: true,
      });
      let id = '';
      let content = '';
      for await (const event of stream) {
        id = event.id;
        content += event.choices[0]?.delta.content ?? '';
      }
      expect(content).toBe(answer);
      const receipt = await client.verifyResponse(id);
      expect(receipt.attestations.map(({ instanceId }) => instanceId)).toEqual([
        'instance-0',
        'instance-1',
      ]);
      expect(provider.state.decryptedPrompts).toEqual([prompt, prompt]);
      expect(provider.state.attestationRequests).toBe(1);
      expect(provider.state.verifiedQuotes).toHaveLength(3);
      expect(provider.state.signatureRequests).toBe(2);
      expect(
        provider.state.requests.every(
          ({ headers }) => headers.has('x-client-pub-key') === e2ee,
        ),
      ).toBe(true);
      expect(
        endpoint.requests.map((request) => new URL(request.url).pathname),
      ).toEqual([
        '/v1/attestation/report',
        '/ohttp',
        `/v1/signature/${completion.id}`,
        '/ohttp',
        `/v1/signature/${id}`,
      ]);
      for (const request of endpoint.requests) {
        expect(request.headers.get('authorization')).toBe(
          'Bearer direct-test-key',
        );
        expect(request.headers.get('x-proxy-token')).toBe('proxy-test-token');
      }
    },
  );

  test.each([true, false])(
    'uses another verified report of the serving signer when its public key is omitted and E2EE is %s',
    async (e2ee) => {
      const provider = createDirectEndpoint({
        otherSignerFirst: true,
        omitPublicKeyFor: [0],
      });
      const endpoint = await createOhttpEndpoint({
        fetch: provider.fetch,
        signingKey: nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7)),
      });
      jest.spyOn(globalThis, 'fetch').mockImplementation(endpoint.fetch);
      const client = new DirectInferenceClient({
        ...provider.options,
        ohttp: true,
        signingAlgo: 'ed25519',
        e2ee,
      });
      const completion = await client.chat.completions.create({
        model,
        messages,
      });
      expect(completion.choices[0].message.content).toBe(answer);
      expect(provider.state.decryptedPrompts).toEqual([prompt]);
      expect(provider.state.requests[0].headers.get('x-model-pub-key')).toBe(
        provider.publicKey,
      );
      const receipt = await client.verifyResponse(completion.id);
      expect(receipt.attestations.map(({ instanceId }) => instanceId)).toEqual([
        'instance-0',
        'instance-1',
      ]);
      expect(provider.state.verifiedQuotes).toHaveLength(3);
    },
  );

  test('rejects OHTTP when only an unrelated signer supplies a public key', async () => {
    const provider = createDirectEndpoint({
      otherSignerFirst: true,
      omitPublicKeyFor: [0, 1],
    });
    const endpoint = await createOhttpEndpoint({
      fetch: provider.fetch,
      signingKey: nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7)),
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(endpoint.fetch);
    const client = new DirectInferenceClient({
      ...provider.options,
      ohttp: true,
      signingAlgo: 'ed25519',
    });
    await expect(client.fetch(chatRequest())).rejects.toMatchObject({
      failure: { code: 'e2ee.model_public_key_required' },
    });
    expect(provider.state.verifiedQuotes).toHaveLength(3);
    expect(
      endpoint.requests.map((request) => new URL(request.url).pathname),
    ).toEqual(['/v1/attestation/report']);
  });

  test.each(['missing', 'other-instance-signed'] as const)(
    'blocks direct Chat when OHTTP evidence is %s',
    async (evidence) => {
      const provider = createDirectEndpoint({ additionalSigner: true });
      const endpoint = await createOhttpEndpoint({
        fetch: provider.fetch,
        signingKey: nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 8)),
      });
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(
          evidence === 'missing' ? provider.fetch : endpoint.fetch,
        );
      const client = new DirectInferenceClient({
        ...provider.options,
        ohttp: true,
        signingAlgo: 'ed25519',
      });
      await expect(client.fetch(chatRequest())).rejects.toMatchObject({
        failure: {
          code:
            evidence === 'missing'
              ? 'ohttp.attestation_required'
              : 'ohttp.signer_mismatch',
        },
      });
      expect(provider.state.verifiedQuotes).toHaveLength(3);
      expect(provider.state.completionRequests).toBe(0);
      expect(
        endpoint.requests.every(
          (request) => new URL(request.url).pathname !== '/ohttp',
        ),
      ).toBe(true);
    },
  );

  test('rejects the receipt when the final OHTTP authentication is truncated after SSE DONE', async () => {
    const provider = createDirectEndpoint();
    const endpoint = await createOhttpEndpoint({
      fetch: provider.fetch,
      signingKey: nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7)),
      truncateResponse: true,
    });
    jest.spyOn(globalThis, 'fetch').mockImplementation(endpoint.fetch);
    const client = new DirectInferenceClient({
      ...provider.options,
      ohttp: true,
      signingAlgo: 'ed25519',
    });
    const stream = await client.chat.completions.create({
      model,
      messages,
      stream: true,
    });
    let id = '';
    let content = '';
    for await (const event of stream) {
      id = event.id;
      content += event.choices[0]?.delta.content ?? '';
    }
    expect(content).toBe(answer);
    endpoint.finishResponse();
    await expect(client.verifyResponse(id)).rejects.toMatchObject({
      failure: { code: 'ohttp.decryption_failed' },
    });
    expect(provider.state.signatureRequests).toBe(0);
  });

  test('requires a direct base URL at runtime', () => {
    const createClientWithoutBaseUrl = () => {
      // @ts-expect-error JavaScript callers can omit a required property.
      return new DirectInferenceClient({ apiKey: 'direct-key' });
    };

    expect(createClientWithoutBaseUrl).toThrow('[api.invalid_input]');
  });

  test('encrypts by default after checking every deployment and retains both same-signer reports', async () => {
    const endpoint = createDirectEndpoint();
    const checked: string[] = [];
    const client = new DirectInferenceClient({
      ...endpoint.options,
      deploymentPolicy: async ({ model: requestedModel, deployment }) => {
        expect(requestedModel).toBe(model);
        expect(endpoint.state.completionRequests).toBe(0);
        await Promise.resolve();
        checked.push(deployment.appCompose);
      },
    });

    const response = await client.chat.completions.create({ model, messages });
    expect(response.choices[0].message.content).toBe(answer);
    expect(checked).toEqual(composes);
    expect(endpoint.state.verifiedQuotes).toHaveLength(2);
    expect(endpoint.state.decryptedPrompts).toEqual([prompt]);
    const sent = endpoint.state.requests[0];
    expect(sent.body.messages[0].content).not.toBe(prompt);
    expect(sent.headers.get('x-model-pub-key')).toBe(endpoint.publicKey);
    expect(sent.headers.get('x-encryption-version')).toBe('2');

    const receipt = await client.verifyResponse(response.id);
    expect(receipt.signatureKind).toBe('provider_tee');
    expect(receipt.attestations.map((item) => item.instanceId)).toEqual([
      'instance-0',
      'instance-1',
    ]);
    expect(
      receipt.attestations.map((item) => item.deployment.appCompose),
    ).toEqual(composes);
    expect(
      receipt.attestations.every(
        (item) => item.signer.signingAddress === endpoint.publicKey,
      ),
    ).toBe(true);
  });

  test('supports OpenAI fetch injection, encrypted streaming and byte-exact verification', async () => {
    const endpoint = createDirectEndpoint();
    const client = new DirectInferenceClient(endpoint.options);
    const openai = new OpenAI({
      baseURL: client.getBaseUrl(),
      apiKey: 'test-only',
      fetch: client.fetch,
    });
    const stream = await openai.chat.completions.create({
      model,
      messages,
      stream: true,
    });
    let id = '';
    let text = '';
    for await (const event of stream) {
      id = event.id;
      text += event.choices[0]?.delta.content ?? '';
    }
    expect(text).toBe(answer);
    expect(endpoint.state.decryptedPrompts).toEqual([prompt]);
    expect(endpoint.state.requests[0].body.messages[0].content).not.toBe(
      prompt,
    );
    const receipt = await client.verifyResponse(id);
    expect(receipt.completionId).toBe(id);
    expect(receipt.attestations).toHaveLength(2);
    expect(endpoint.state.signatureRequests).toBe(1);
  });

  test('uses the selected signer group for Node TLS pins and response verification', async () => {
    const endpoint = createDirectEndpoint({ additionalSigner: true });
    jest
      .spyOn(nodeTls, 'requestHttps')
      .mockImplementation(async ({ request }) => ({
        response: await endpoint.fetch(request),
        peerSpkiFingerprint: spkiFingerprints[0],
      }));
    const createPinnedFetch = jest
      .spyOn(nodeTls, 'createPinnedTlsFetch')
      .mockReturnValue(endpoint.fetch);
    const client = new NodeDirectInferenceClient(endpoint.options);

    const response = await client.chat.completions.create({ model, messages });
    expect(endpoint.state.verifiedQuotes).toHaveLength(3);
    expect(endpoint.state.decryptedPrompts).toEqual([prompt]);
    expect(createPinnedFetch).toHaveBeenCalledWith(
      spkiFingerprints.slice(0, 2),
    );

    const receipt = await client.verifyResponse(response.id);
    expect(receipt.attestations.map((item) => item.instanceId)).toEqual([
      'instance-0',
      'instance-1',
    ]);
    expect(receipt.attestations.map((item) => item.spkiFingerprint)).toEqual(
      spkiFingerprints.slice(0, 2),
    );
  });

  test.each([true, false])(
    'rejects a response signed by another verified key with E2EE set to %s',
    async (e2ee) => {
      const endpoint = createDirectEndpoint({
        additionalSigner: true,
        wrongSignatureKey: true,
      });
      const client = new DirectInferenceClient({ ...endpoint.options, e2ee });

      const response = await client.chat.completions.create({
        model,
        messages,
      });
      expect(response.choices[0].message.content).toBe(answer);
      expect(endpoint.state.verifiedQuotes).toHaveLength(3);
      await expect(client.verifyResponse(response.id)).rejects.toMatchObject({
        failure: { code: 'signature.signer_mismatch' },
      });
    },
  );

  test('allows plaintext fetch without skipping preflight or response verification', async () => {
    const endpoint = createDirectEndpoint();
    const client = new DirectInferenceClient({
      ...endpoint.options,
      e2ee: false,
    });
    const response = await client.fetch(chatRequest());
    const completion = await response.json();
    expect(completion.choices[0].message.content).toBe(answer);
    expect(endpoint.state.verifiedQuotes).toHaveLength(2);
    expect(endpoint.state.requests[0].body.messages[0].content).toBe(prompt);
    expect(endpoint.state.requests[0].headers.has('x-client-pub-key')).toBe(
      false,
    );
    const receipt = await client.verifyResponse(completion.id);
    expect(receipt.attestations).toHaveLength(2);
  });

  test('sends no chat request when the second same-signer quote is rejected', async () => {
    const endpoint = createDirectEndpoint({ invalidSecondQuote: true });
    const client = new DirectInferenceClient(endpoint.options);
    await expect(client.fetch(chatRequest())).rejects.toMatchObject({
      failure: { code: 'policy.debug_enabled' },
    });
    expect(endpoint.state.verifiedQuotes).toHaveLength(2);
    expect(endpoint.state.completionRequests).toBe(0);
  });

  test('sends no chat request when policy rejects the second deployment', async () => {
    const endpoint = createDirectEndpoint();
    const checked: string[] = [];
    const client = new DirectInferenceClient({
      ...endpoint.options,
      deploymentPolicy: async ({ deployment }) => {
        await Promise.resolve();
        checked.push(deployment.appCompose);
        if (deployment.appCompose === composes[1]) {
          throw new Error('Deployment is not approved');
        }
      },
    });
    await expect(client.fetch(chatRequest())).rejects.toMatchObject({
      failure: { code: 'provenance.verification_failed' },
    });
    expect(checked).toEqual(composes);
    expect(endpoint.state.completionRequests).toBe(0);
  });

  test('reuses the verified report for repeated same-model requests by default', async () => {
    const endpoint = createDirectEndpoint();
    const client = new DirectInferenceClient(endpoint.options);
    const first = await client.chat.completions.create({ model, messages });
    const second = await client.chat.completions.create({ model, messages });
    expect(endpoint.state.attestationRequests).toBe(1);
    expect(endpoint.state.verifiedQuotes).toHaveLength(2);
    expect(endpoint.state.completionRequests).toBe(2);
    expect((await client.verifyResponse(first.id)).completionId).toBe(first.id);
    expect((await client.verifyResponse(second.id)).completionId).toBe(
      second.id,
    );
  });

  test.each([
    {
      name: 'changed response bytes',
      endpoint: { alterResponseBytes: true },
      code: 'signature.payload_mismatch',
    },
    {
      name: 'an unverified signer',
      endpoint: { wrongSignatureKey: true },
      code: 'signature.signer_mismatch',
    },
  ])(
    'rejects $name during verifyResponse',
    async ({ endpoint: params, code }) => {
      const endpoint = createDirectEndpoint(params);
      const client = new DirectInferenceClient(endpoint.options);
      const response = await client.chat.completions.create({
        model,
        messages,
      });
      expect(response.choices[0].message.content).toBe(answer);
      await expect(client.verifyResponse(response.id)).rejects.toMatchObject({
        failure: { code },
      });
    },
  );
});
