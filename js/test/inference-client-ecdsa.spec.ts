import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { ethers } from 'ethers';
import { InferenceClient, type QuoteVerificationResult } from '../src';
import { decryptE2eeText, encryptE2eeText } from '../src/core/e2ee';
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
}): QuoteVerificationResult {
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
  readonly quoteVerifier: (quote: string) => QuoteVerificationResult;
  readonly state: EcdsaGatewayState;
} {
  const quotes = new Map<string, QuoteVerificationResult>();
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
    quoteVerifier(quote: string): QuoteVerificationResult {
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

  test('verifies, encrypts, decrypts, and verifies a receipt with ECDSA', async () => {
    const gateway = createEcdsaGateway();
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      baseUrl,
      headers: { authorization: 'Bearer test-token' },
      signingAlgo: 'ecdsa',
      gatewayVerification: { verifiers: { quote: gateway.quoteVerifier } },
      modelVerification: { verifiers: { quote: gateway.quoteVerifier } },
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
      completionId: 'chatcmpl-ecdsa',
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
    expect(headers.get('x-encryption-version')).toBeNull();
    expect(headers.get('x-encrypt-all-fields')).toBe('true');
  });

  test('verifies an ECDSA Gateway receipt when the Gateway signs the response', async () => {
    const gateway = createEcdsaGateway({ signatureKind: 'gateway' });
    jest.spyOn(globalThis, 'fetch').mockImplementation(gateway.fetch);
    const client = new InferenceClient({
      baseUrl,
      headers: { authorization: 'Bearer test-token' },
      signingAlgo: 'ecdsa',
      gatewayVerification: { verifiers: { quote: gateway.quoteVerifier } },
      modelVerification: { verifiers: { quote: gateway.quoteVerifier } },
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
      completionId: 'chatcmpl-ecdsa',
      signatureKind: 'gateway',
    });
  });
});
