import { Buffer } from 'node:buffer';
import nacl from 'tweetnacl';
import { InferenceClient, type TdxQuoteVerificationResult } from '../src';
import {
  CHUTES_TEST_PUBLIC_KEY,
  createChutesAttestation,
  createChutesQuote,
} from './chutes-fixtures';
import { appCompose, createGatewayTlsQuote, sha256 } from './fixtures';

const baseUrl = 'https://chutes-gateway.test/v1/';
const model = 'chutes-test-model';
const completionId = 'chatcmpl-chutes';

type MockGatewayOptions = {
  readonly replacePublicKey?: boolean;
  readonly rejectGpu?: boolean;
  readonly tamperResponse?: boolean;
};

/** In-memory HTTP plus mocked DCAP/NRAS; all key/hash/signature checks are real. */
function createMockGateway(options: MockGatewayOptions = {}) {
  const gatewayKey = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 17));
  const gatewayAddress = Buffer.from(gatewayKey.publicKey).toString('hex');
  const advertisedPublicKey = options.replacePublicKey
    ? Buffer.alloc(1184, 43).toString('base64')
    : CHUTES_TEST_PUBLIC_KEY;
  const quotes = new Map<string, TdxQuoteVerificationResult>();
  const modelQueries: URLSearchParams[] = [];
  const chats: {
    headers: Headers;
    requestBytes: Buffer;
    responseBytes: Buffer;
  }[] = [];
  let modelNonce = '';
  let signature: Record<string, string> | undefined;
  const tdxQuote = jest.fn((quoteId: string) => {
    const quote = quotes.get(quoteId);
    if (quote === undefined)
      throw new Error(`Unexpected test quote ${quoteId}`);
    return quote;
  });
  const gpuEvidence = jest.fn(async (payload: string) => {
    const decoded = JSON.parse(payload);
    expect(decoded).toEqual({
      nonce: sha256(modelNonce + advertisedPublicKey).toString('hex'),
      arch: 'HOPPER',
      evidence_list: createChutesAttestation().gpuEvidence.map(
        ({ certificate, evidence }) => ({
          certificate,
          evidence,
        }),
      ),
    });
    if (options.rejectGpu) throw new Error('Synthetic NRAS rejection');
  });

  jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    expect(request.headers.get('authorization')).toBe('Bearer test-key');
    if (url.pathname === '/v1/attestation/report') {
      const nonce = url.searchParams.get('nonce');
      if (nonce === null) throw new Error('Missing client nonce');
      if (url.searchParams.has('model')) {
        modelQueries.push(url.searchParams);
        modelNonce = nonce;
        const attestation = createChutesAttestation({ nonce });
        quotes.set(
          attestation.intelQuote,
          createChutesQuote({ binding: attestation }),
        );
        return Response.json({
          model_attestations: [
            {
              provider: 'chutes',
              model,
              nonce,
              quote_b64: Buffer.from(attestation.intelQuote, 'hex').toString(
                'base64',
              ),
              certificate_b64: attestation.certificate,
              e2e_pubkey: advertisedPublicKey,
              gpu_evidence: attestation.gpuEvidence,
              instance_id: attestation.instanceId,
              verified: true,
              gpu_verdict: 'PASS',
              measurement_config: 'untrusted display metadata',
            },
          ],
        });
      }
      const quoteId = `gateway:${nonce}`;
      const quote = createGatewayTlsQuote({
        reportData: Buffer.concat([
          Buffer.from(gatewayKey.publicKey),
          Buffer.from(nonce, 'hex'),
        ]),
      });
      quotes.set(quoteId, quote);
      return Response.json({
        gateway_attestation: {
          request_nonce: nonce,
          signing_algo: 'ed25519',
          signing_address: gatewayAddress,
          intel_quote: quoteId,
          report_data: Buffer.from(quote.reportData).toString('hex'),
          event_log: [
            {
              digest: '00'.repeat(48),
              imr: 3,
              event_type: 0,
              event: 'compose-hash',
              event_payload: 'beef',
            },
          ],
          info: { tcb_info: { app_compose: appCompose } },
        },
      });
    }
    if (url.pathname === `/v1/signature/${completionId}`) {
      if (signature === undefined)
        throw new Error('Signature requested before completion');
      expect(url.searchParams.get('signing_algo')).toBe('ed25519');
      return Response.json(signature);
    }
    if (url.pathname !== '/v1/chat/completions') {
      throw new Error(`Unexpected test request: ${url.pathname}`);
    }
    const requestBytes = Buffer.from(await request.arrayBuffer());
    const body = JSON.parse(requestBytes.toString('utf8'));
    const content = body.stream
      ? [
          ': gateway comment\r\n\r\n',
          `data: ${JSON.stringify({ id: completionId, object: 'chat.completion.chunk', created: 0, model, choices: [{ index: 0, delta: { content: 'hello ' }, finish_reason: null }] })}\r\n\r\n`,
          `data: ${JSON.stringify({ id: completionId, object: 'chat.completion.chunk', created: 0, model, choices: [{ index: 0, delta: { content: '世界' }, finish_reason: 'stop' }] })}\n\n`,
          'data: [DONE]\n\n: response complete\n\n',
        ].join('')
      : `${JSON.stringify({ id: completionId, object: 'chat.completion', created: 0, model, choices: [{ index: 0, message: { role: 'assistant', content: 'hello 世界' }, finish_reason: 'stop' }] }, null, 2)}\n`;
    const responseBytes = Buffer.from(content);
    const text = `${sha256(requestBytes).toString('hex')}:${sha256(responseBytes).toString('hex')}`;
    signature = {
      text,
      signature: Buffer.from(
        nacl.sign.detached(Buffer.from(text), gatewayKey.secretKey),
      ).toString('hex'),
      signing_algo: 'ed25519',
      signing_address: gatewayAddress,
      signature_kind: 'gateway',
    };
    chats.push({ headers: request.headers, requestBytes, responseBytes });
    return new Response(
      options.tamperResponse ? content.replace('hello', 'tampered') : content,
      {
        headers: {
          'content-type': body.stream
            ? 'text/event-stream'
            : 'application/json',
        },
      },
    );
  });

  return {
    modelQueries,
    chats,
    tdxQuote,
    gpuEvidence,
    client(e2ee?: boolean) {
      return new InferenceClient({
        baseUrl,
        apiKey: 'test-key',
        ...(e2ee === undefined ? {} : { e2ee }),
        gatewayVerification: { verifiers: { tdxQuote } },
        modelVerification: { verifiers: { tdxQuote, gpuEvidence } },
      });
    },
  };
}

function expectRoutingOnly(headers: Headers): void {
  expect(headers.get('x-model-pub-key')).toBe(CHUTES_TEST_PUBLIC_KEY);
  expect(headers.get('x-no-aliasing')).toBe('true');
  for (const name of [
    'x-client-pub-key',
    'x-signing-algo',
    'x-encryption-version',
    'x-encrypt-all-fields',
  ]) {
    expect(headers.has(name)).toBe(false);
  }
}

describe('Chutes Gateway inference client', () => {
  afterEach(() => jest.restoreAllMocks());

  test('defaults to verified, routing-only Chutes and verifies the Gateway signature', async () => {
    const gateway = createMockGateway();
    const client = gateway.client();
    const completion = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'hello model' }],
    });
    expect(completion.choices[0].message.content).toBe('hello 世界');
    expect(gateway.modelQueries[0].has('provider')).toBe(false);
    expect(gateway.tdxQuote).toHaveBeenCalledTimes(2);
    expect(gateway.gpuEvidence).toHaveBeenCalledTimes(1);
    expectRoutingOnly(gateway.chats[0].headers);
    expect(
      JSON.parse(gateway.chats[0].requestBytes.toString()).messages[0].content,
    ).toBe('hello model');
    const verified = await client.verifyResponse(completion.id);
    expect(verified.signatureKind).toBe('gateway');
    expect(verified.signature.signedText).toBe(
      `${sha256(gateway.chats[0].requestBytes).toString('hex')}:${sha256(gateway.chats[0].responseBytes).toString('hex')}`,
    );
    expect(sha256(gateway.chats[0].responseBytes)).not.toEqual(
      sha256(JSON.stringify(completion)),
    );
  });

  test('verifies a consumed stream using the complete original SSE bytes', async () => {
    const gateway = createMockGateway();
    const client = gateway.client();
    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: 'stream please' }],
      stream: true,
    });
    let content = '';
    for await (const chunk of stream)
      content += chunk.choices[0]?.delta.content ?? '';
    expect(content).toBe('hello 世界');
    expectRoutingOnly(gateway.chats[0].headers);
    const result = await client.verifyResponse(completionId);
    expect(result.signatureKind).toBe('gateway');
    expect(result.signature.signedText).toBe(
      `${sha256(gateway.chats[0].requestBytes).toString('hex')}:${sha256(gateway.chats[0].responseBytes).toString('hex')}`,
    );
    expect(gateway.chats[0].responseBytes.toString()).toContain(
      ': response complete',
    );
  });

  test('explicit E2EE requests NEAR and refuses a Chutes-only report before Chat', async () => {
    const gateway = createMockGateway();
    const client = gateway.client(true);
    await expect(
      client.fetch(`${baseUrl}chat/completions`, {
        method: 'POST',
        body: JSON.stringify({ model, messages: [] }),
      }),
    ).rejects.toMatchObject({
      name: 'ApiError',
      failure: {
        code: 'api.invalid_response',
        details: {
          path: 'model_attestations[0].provider',
          expected: 'near',
          actual: 'chutes',
        },
      },
    });
    expect(gateway.modelQueries[0].get('provider')).toBe('near');
    expect(gateway.chats).toHaveLength(0);
    expect(gateway.gpuEvidence).not.toHaveBeenCalled();
  });

  test.each([
    {
      options: { replacePublicKey: true },
      code: 'binding.report_data_mismatch',
    },
    { options: { rejectGpu: true }, code: 'gpu.attestation_rejected' },
  ])('does not send Chat after $code', async ({ options, code }) => {
    const gateway = createMockGateway(options);
    await expect(
      gateway.client().fetch(`${baseUrl}chat/completions`, {
        method: 'POST',
        body: JSON.stringify({ model, messages: [] }),
      }),
    ).rejects.toMatchObject({ failure: { code } });
    expect(gateway.chats).toHaveLength(0);
  });

  test('rejects changed response bytes rather than trusting Gateway signature metadata', async () => {
    const gateway = createMockGateway({ tamperResponse: true });
    const client = gateway.client();
    const completion = await client.chat.completions.create({
      model,
      messages: [],
    });
    await expect(client.verifyResponse(completion.id)).rejects.toMatchObject({
      failure: { code: 'signature.payload_mismatch' },
    });
  });
});
