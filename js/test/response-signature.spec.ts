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
  createModelAttestation,
  createQuote,
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
    clientBinding: { nonce },
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
      declaredSpkiFingerprint: tlsFingerprint,
      reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
    },
    clientBinding: { nonce, peerSpkiFingerprint: tlsFingerprint },
    verifiers: { quote: async () => quote },
  });
}

describe('response signature verification', () => {
  test('verifies a canonical model response when signer encodings differ', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const signedText = modelSignedText({
      model: 'canonical-model',
      request: requestBody,
      response: responseBody,
    });
    const signature: CompletionSignature = {
      kind: 'provider_tee',
      signedText,
      signature: await wallet.signMessage(signedText),
      signer: {
        signingAlgo: 'ecdsa',
        signingAddress: wallet.address.slice(2).toUpperCase(),
      },
    };

    const attestation = await verifiedModelAttestation(wallet.address);

    verifyModelResponse({
      requestBody,
      responseBody,
      signature,
      attestation,
    });
  });

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

    const attestation = await verifiedGatewayAttestation(signingAddress);

    verifyGatewayResponse({
      requestBody,
      responseBody,
      signature,
      attestation,
    });
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

    expect(() =>
      verifyGatewayResponse({
        requestBody,
        responseBody,
        signature,
        attestation,
      }),
    ).toThrow(
      expect.objectContaining({
        failure: { code: 'signature.signer_mismatch' },
      }),
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

    expect(() =>
      verifyModelResponse({
        requestBody,
        responseBody,
        signature,
        attestation,
      }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          code: 'signature.kind_mismatch',
          details: { expected: 'provider_tee', actual: 'gateway' },
        },
      }),
    );
  });
});
