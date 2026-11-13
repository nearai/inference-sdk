import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import type { CompletionSignature } from '../src';
import {
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '../src';
import {
  createGatewayTlsQuote,
  createModelAttestation,
  createModelQuote,
  nonce,
  tlsFingerprint,
} from './fixtures';

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');
type ModelSignedTextParams = {
  model: string;
  request: Uint8Array;
  response: Uint8Array;
};

function hashBytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function modelSignedText({
  model,
  request,
  response,
}: ModelSignedTextParams): string {
  return `${model}:${hashBytes(request)}:${hashBytes(response)}`;
}

function gatewaySignedText(request: Uint8Array, response: Uint8Array): string {
  return `${hashBytes(request)}:${hashBytes(response)}`;
}

function gatewayQuoteForSigner(signingAddress: string) {
  const signingAddressHex = signingAddress.startsWith('0x')
    ? signingAddress.slice(2)
    : signingAddress;
  const signerTlsBinding = createHash('sha256')
    .update(
      Buffer.concat([
        Buffer.from(signingAddressHex, 'hex'),
        Buffer.from(tlsFingerprint, 'hex'),
      ]),
    )
    .digest();
  return createGatewayTlsQuote({
    reportData: Buffer.concat([signerTlsBinding, Buffer.from(nonce, 'hex')]),
  });
}

function modelQuoteForSigner(signingAddress: string) {
  const signingAddressHex = signingAddress.startsWith('0x')
    ? signingAddress.slice(2)
    : signingAddress;
  const signerBinding = Buffer.alloc(32);
  Buffer.from(signingAddressHex, 'hex').copy(signerBinding);
  return createModelQuote({
    reportData: Buffer.concat([signerBinding, Buffer.from(nonce, 'hex')]),
  });
}

async function verifiedModelAttestation(
  signingAddress: string,
  signingAlgo: CompletionSignature['signer']['signingAlgo'] = 'ecdsa',
) {
  const quote = modelQuoteForSigner(signingAddress);
  return verifyModelAttestation({
    attestation: createModelAttestation({
      signer: { signingAlgo, signingAddress },
    }),
    clientBinding: { nonce },
    verifiers: { tdxQuote: async () => quote },
  });
}

async function verifiedGatewayAttestation(
  signingAddress: string,
  signingAlgo: CompletionSignature['signer']['signingAlgo'] = 'ed25519',
): Promise<Awaited<ReturnType<typeof verifyGatewayAttestation>>> {
  const quote = gatewayQuoteForSigner(signingAddress);
  return verifyGatewayAttestation({
    attestation: {
      ...createModelAttestation({
        signer: { signingAlgo, signingAddress },
      }),
      spkiFingerprint: tlsFingerprint,
      reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
    },
    clientBinding: { nonce, spkiFingerprint: tlsFingerprint },
    verifiers: { tdxQuote: async () => quote },
  });
}

describe('response signature verification', () => {
  test('rejects a model signature that names a different model', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const aliasedRequestBody = Buffer.from('{"model":"alias"}');
    const signedText = modelSignedText({
      model: 'canonical-model',
      request: aliasedRequestBody,
      response: responseBody,
    });
    const signature: CompletionSignature = {
      kind: 'provider_tee',
      signedText,
      signature: await wallet.signMessage(signedText),
      signer: { signingAlgo: 'ecdsa', signingAddress: wallet.address },
    };
    const attestation = await verifiedModelAttestation(wallet.address);

    expect(() =>
      verifyModelResponse({
        requestBody: aliasedRequestBody,
        responseBody,
        signature,
        attestation,
      }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          code: 'signature.payload_mismatch',
          details: { source: 'signed_payload', reason: 'text_mismatch' },
        },
      }),
    );
  });

  test.each([
    {
      label: 'invalid JSON',
      request: Buffer.from('{'),
      reason: 'invalid_json',
    },
    {
      label: 'a missing model',
      request: Buffer.from('{}'),
      reason: 'missing_model',
    },
    {
      label: 'an empty model',
      request: Buffer.from('{"model":""}'),
      reason: 'missing_model',
    },
  ])(
    'rejects a model response request with $label',
    async ({ request, reason }) => {
      const wallet = new ethers.Wallet(
        '0x0123456789012345678901234567890123456789012345678901234567890123',
      );
      const attestation = await verifiedModelAttestation(wallet.address);
      const signature: CompletionSignature = {
        kind: 'provider_tee',
        signedText: 'unused',
        signature: '00',
        signer: { signingAlgo: 'ecdsa', signingAddress: wallet.address },
      };

      expect(() =>
        verifyModelResponse({
          requestBody: request,
          responseBody,
          signature,
          attestation,
        }),
      ).toThrow(
        expect.objectContaining({
          failure: {
            code: 'signature.payload_mismatch',
            details: { source: 'request_model', reason },
          },
        }),
      );
    },
  );

  describe.each(['ed25519', 'ecdsa'] as const)('%s', (signingAlgo) => {
    describe.each(['provider_tee', 'gateway'] as const)('%s', (kind) => {
      test.each([
        { change: 'none', code: undefined },
        { change: 'request bytes', code: 'signature.payload_mismatch' },
        { change: 'response bytes', code: 'signature.payload_mismatch' },
        { change: 'signature bytes', code: 'signature.invalid' },
        { change: 'signer', code: 'signature.signer_mismatch' },
        { change: 'kind', code: 'signature.kind_mismatch' },
      ])(
        'binds exact bytes, signer and kind: change=$change',
        async ({ change, code }) => {
          const wallet = new ethers.Wallet(
            '0x0123456789012345678901234567890123456789012345678901234567890123',
          );
          const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
          const signingAddress =
            signingAlgo === 'ecdsa'
              ? wallet.address
              : Buffer.from(keyPair.publicKey).toString('hex');
          const signedText =
            kind === 'provider_tee'
              ? modelSignedText({
                  model: 'canonical-model',
                  request: requestBody,
                  response: responseBody,
                })
              : gatewaySignedText(requestBody, responseBody);
          const signatureHex =
            signingAlgo === 'ecdsa'
              ? await wallet.signMessage(signedText)
              : Buffer.from(
                  nacl.sign.detached(
                    Buffer.from(signedText),
                    keyPair.secretKey,
                  ),
                ).toString('hex');
          const signature: CompletionSignature = {
            kind,
            signedText,
            signature:
              kind === 'provider_tee'
                ? signatureHex.replace(/^0x/, '')
                : signatureHex,
            signer: {
              signingAlgo,
              signingAddress: `0X${signingAddress.replace(/^0x/i, '').toUpperCase()}`,
            },
          };
          // Signature and evidence use equivalent, differently spelled signer bytes.
          const attestedSigningAddress =
            change === 'signer'
              ? '11'.repeat(signingAlgo === 'ecdsa' ? 20 : 32)
              : signingAddress;
          const modelAttestation = await verifiedModelAttestation(
            attestedSigningAddress,
            signingAlgo,
          );
          const gatewayAttestation = await verifiedGatewayAttestation(
            attestedSigningAddress,
            signingAlgo,
          );
          let request = requestBody;
          let response = responseBody;
          if (change === 'request bytes')
            request = Buffer.concat([request, Buffer.from(' ')]);
          if (change === 'response bytes')
            response = Buffer.concat([response, Buffer.from(' ')]);
          const alteredSignature = { ...signature };
          if (change === 'signature bytes') {
            const bytes = Buffer.from(
              signature.signature.replace(/^0x/, ''),
              'hex',
            );
            bytes[0] ^= 1;
            alteredSignature.signature = bytes.toString('hex');
          }
          if (change === 'kind')
            alteredSignature.kind =
              kind === 'gateway' ? 'provider_tee' : 'gateway';
          const verify = () => {
            const params = {
              requestBody: request,
              responseBody: response,
              signature: alteredSignature,
            };
            if (kind === 'provider_tee')
              verifyModelResponse({ ...params, attestation: modelAttestation });
            else
              verifyGatewayResponse({
                ...params,
                attestation: gatewayAttestation,
              });
          };
          if (code === undefined) expect(verify).not.toThrow();
          else
            expect(verify).toThrow(
              expect.objectContaining({
                failure: expect.objectContaining({
                  code,
                  ...(change === 'kind'
                    ? {
                        details: {
                          expected: kind,
                          actual: alteredSignature.kind,
                        },
                      }
                    : {}),
                }),
              }),
            );
        },
      );
    });
  });
});
