import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import type { CompletionSignature } from '../../src';
import {
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '../../src';
import {
  createModelAttestation,
  createQuote,
  nonce,
  tlsFingerprint,
} from '../fixtures';

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');

function hashBytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function modelSignedText(
  model: string,
  request: Uint8Array,
  response: Uint8Array,
): string {
  return `${model}:${hashBytes(request)}:${hashBytes(response)}`;
}

function gatewaySignedText(request: Uint8Array, response: Uint8Array): string {
  return `${hashBytes(request)}:${hashBytes(response)}`;
}

function quoteForSigner(signingAddress: string) {
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
  return createQuote({
    reportData: Buffer.concat([signerTlsBinding, Buffer.from(nonce, 'hex')]),
  });
}

async function verifiedModelAttestation(signingAddress: string) {
  const quote = quoteForSigner(signingAddress);
  return verifyModelAttestation({
    attestation: createModelAttestation({
      signer: { signingAlgo: 'ecdsa', signingAddress },
    }),
    nonce,
    verifiers: { quote: async () => quote },
  });
}

async function verifiedGatewayAttestation(
  signingAddress: string,
): Promise<Awaited<ReturnType<typeof verifyGatewayAttestation>>> {
  const quote = quoteForSigner(signingAddress);
  return verifyGatewayAttestation({
    attestation: {
      ...createModelAttestation({
        signer: { signingAlgo: 'ed25519', signingAddress },
      }),
      reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
    },
    nonce,
    peerSpkiFingerprint: tlsFingerprint,
    verifiers: { quote: async () => quote },
  });
}

function expectVerificationFailure(
  action: () => unknown,
  failure: Record<string, unknown>,
): void {
  try {
    action();
  } catch (error) {
    expect(error).toMatchObject({ failure });
    return;
  }
  throw new Error('Expected verification to fail');
}

describe('response signature verification', () => {
  test('verifies a canonical model response signature', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const signedText = modelSignedText(
      'canonical-model',
      requestBody,
      responseBody,
    );
    const signature: CompletionSignature = {
      kind: 'provider_tee',
      signedText,
      signature: await wallet.signMessage(signedText),
      signer: { signingAlgo: 'ecdsa', signingAddress: wallet.address },
    };

    expect(
      verifyModelResponse({
        requestBody,
        responseBody,
        signature,
        attestation: await verifiedModelAttestation(wallet.address),
      }),
    ).toBeUndefined();
  });

  test('rejects a model signature that names a different model', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const aliasedRequestBody = Buffer.from('{"model":"alias"}');
    const signedText = modelSignedText(
      'canonical-model',
      aliasedRequestBody,
      responseBody,
    );
    const signature: CompletionSignature = {
      kind: 'provider_tee',
      signedText,
      signature: await wallet.signMessage(signedText),
      signer: { signingAlgo: 'ecdsa', signingAddress: wallet.address },
    };
    const attestation = await verifiedModelAttestation(wallet.address);

    expectVerificationFailure(
      () =>
        verifyModelResponse({
          requestBody: aliasedRequestBody,
          responseBody,
          signature,
          attestation,
        }),
      {
        phase: 'signature',
        code: 'signature.payload_mismatch',
        details: { source: 'signed_payload', reason: 'text_mismatch' },
      },
    );
  });

  test('verifies an Ed25519 gateway response signature', async () => {
    const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
    const signedText = gatewaySignedText(requestBody, responseBody);
    const signingAddress = Buffer.from(keyPair.publicKey).toString('hex');
    const signature: CompletionSignature = {
      kind: 'gateway',
      signedText,
      signature: Buffer.from(
        nacl.sign.detached(Buffer.from(signedText), keyPair.secretKey),
      ).toString('hex'),
      signer: { signingAlgo: 'ed25519', signingAddress },
    };

    expect(
      verifyGatewayResponse({
        requestBody,
        responseBody,
        signature,
        attestation: await verifiedGatewayAttestation(signingAddress),
      }),
    ).toBeUndefined();
  });

  test('rejects a gateway response signed by a different gateway identity', async () => {
    const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
    const signedText = gatewaySignedText(requestBody, responseBody);
    const signingAddress = Buffer.from(keyPair.publicKey).toString('hex');
    const signature: CompletionSignature = {
      kind: 'gateway',
      signedText,
      signature: Buffer.from(
        nacl.sign.detached(Buffer.from(signedText), keyPair.secretKey),
      ).toString('hex'),
      signer: { signingAlgo: 'ed25519', signingAddress },
    };
    const otherKeyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 8));
    const otherSigningAddress = Buffer.from(otherKeyPair.publicKey).toString(
      'hex',
    );
    const attestation = await verifiedGatewayAttestation(otherSigningAddress);

    expectVerificationFailure(
      () =>
        verifyGatewayResponse({
          requestBody,
          responseBody,
          signature,
          attestation,
        }),
      { phase: 'signature', code: 'signature.signer_mismatch' },
    );
  });

  test('rejects an explicit signature kind for the other claim', async () => {
    const signature: CompletionSignature = {
      kind: 'gateway',
      signedText: 'request:response',
      signature: 'aa',
      signer: { signingAlgo: 'ecdsa', signingAddress: '11'.repeat(20) },
    };
    const attestation = await verifiedModelAttestation(
      signature.signer.signingAddress,
    );

    expectVerificationFailure(
      () =>
        verifyModelResponse({
          requestBody,
          responseBody,
          signature,
          attestation,
        }),
      {
        phase: 'signature',
        code: 'signature.kind_mismatch',
        details: { expected: 'provider_tee', actual: 'gateway' },
      },
    );
  });

  test('verifies a response with a serialized model-attestation result', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const attestation = JSON.parse(
      JSON.stringify(await verifiedModelAttestation(wallet.address)),
    );
    const signedText = modelSignedText(
      'canonical-model',
      requestBody,
      responseBody,
    );
    const signature: CompletionSignature = {
      kind: 'provider_tee',
      signedText,
      signature: await wallet.signMessage(signedText),
      signer: { signingAlgo: 'ecdsa', signingAddress: wallet.address },
    };

    expect(
      verifyModelResponse({
        requestBody,
        responseBody,
        signature,
        attestation,
      }),
    ).toBeUndefined();
  });

  test('rejects a response input without an attestation signer', () => {
    expectVerificationFailure(
      () =>
        verifyModelResponse({
          requestBody,
          responseBody,
          signature: {
            kind: 'provider_tee',
            signedText: 'model:request:response',
            signature: '00',
            signer: {
              signingAlgo: 'ecdsa',
              signingAddress: '11'.repeat(20),
            },
          },
          attestation: {} as never,
        }),
      {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'attestation.signer', reason: 'missing' },
      },
    );
  });
});
