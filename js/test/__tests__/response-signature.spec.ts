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

function quoteForSigner(address: string) {
  const addressHex = address.startsWith('0x') ? address.slice(2) : address;
  const signerTlsBinding = createHash('sha256')
    .update(
      Buffer.concat([
        Buffer.from(addressHex, 'hex'),
        Buffer.from(tlsFingerprint, 'hex'),
      ]),
    )
    .digest();
  return createQuote({
    reportData: Buffer.concat([signerTlsBinding, Buffer.from(nonce, 'hex')]),
  });
}

async function verifiedModelAttestation(address: string) {
  const quote = quoteForSigner(address);
  return verifyModelAttestation({
    attestation: createModelAttestation({
      signer: { algorithm: 'ecdsa', address },
    }),
    nonce,
    verifiers: { quote: async () => quote },
  });
}

async function verifiedGatewayAttestation(
  address: string,
): Promise<Awaited<ReturnType<typeof verifyGatewayAttestation>>> {
  const quote = quoteForSigner(address);
  return verifyGatewayAttestation({
    attestation: {
      ...createModelAttestation({
        signer: { algorithm: 'ed25519', address },
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
      signer: { algorithm: 'ecdsa', address: wallet.address },
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
      signer: { algorithm: 'ecdsa', address: wallet.address },
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
    const signerAddress = Buffer.from(keyPair.publicKey).toString('hex');
    const signature: CompletionSignature = {
      kind: 'gateway',
      signedText,
      signature: Buffer.from(
        nacl.sign.detached(Buffer.from(signedText), keyPair.secretKey),
      ).toString('hex'),
      signer: { algorithm: 'ed25519', address: signerAddress },
    };

    expect(
      verifyGatewayResponse({
        requestBody,
        responseBody,
        signature,
        attestation: await verifiedGatewayAttestation(signerAddress),
      }),
    ).toBeUndefined();
  });

  test('rejects an explicit signature kind for the other claim', async () => {
    const signature: CompletionSignature = {
      kind: 'gateway',
      signedText: 'request:response',
      signature: 'aa',
      signer: { algorithm: 'ecdsa', address: '11'.repeat(20) },
    };
    const attestation = await verifiedModelAttestation(
      signature.signer.address,
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

  test('rejects an attestation object that was not verified by this SDK', async () => {
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
      signer: { algorithm: 'ecdsa', address: wallet.address },
    };

    expectVerificationFailure(
      () =>
        verifyModelResponse({
          requestBody,
          responseBody,
          signature,
          attestation: {
            signer: { algorithm: 'ecdsa', address: wallet.address },
          } as never,
        }),
      {
        phase: 'input',
        code: 'input.invalid',
        details: {
          field: 'attestation',
          expected: 'a result returned by verifyModelAttestation',
        },
      },
    );
  });

  test('keeps verified evidence immutable and rejects a reconstructed copy', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const attestation = await verifiedModelAttestation(wallet.address);
    expect(Object.isFrozen(attestation)).toBe(true);
    expect(Object.isFrozen(attestation.signer)).toBe(true);
    const signedText = modelSignedText(
      'canonical-model',
      requestBody,
      responseBody,
    );
    const signature: CompletionSignature = {
      kind: 'provider_tee',
      signedText,
      signature: await wallet.signMessage(signedText),
      signer: { algorithm: 'ecdsa', address: wallet.address },
    };

    expectVerificationFailure(
      () =>
        verifyModelResponse({
          requestBody,
          responseBody,
          signature,
          attestation: { ...attestation } as never,
        }),
      {
        phase: 'input',
        code: 'input.invalid',
        details: { reason: 'unverified_attestation' },
      },
    );
  });
});
