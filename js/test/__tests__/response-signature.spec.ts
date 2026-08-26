import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import {
  gatewaySignatureText,
  providerTeeSignatureText,
  requireKnownSignature,
  verifyGatewayResponse,
  verifyProviderTeeResponse,
} from '../../src';
import {
  VerifiedGatewayAttestation,
  VerifiedNearModelAttestation,
} from '../../src';

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');

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
  test('binds a provider_tee ECDSA signature to the verified model signer', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const text = providerTeeSignatureText(
      'canonical-model',
      requestBody,
      responseBody,
    );
    const signature = await wallet.signMessage(text);
    const attestation: VerifiedNearModelAttestation = {
      kind: 'near_model',
      signingAddress: wallet.address,
      signingAlgo: 'ecdsa',
      reportDataBinding: { kind: 'signer_nonce' },
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      appCompose: '{}',
      imageDigests: [],
      runtimeMeasurements: {},
      provenanceVerified: false,
    };

    expect(
      verifyProviderTeeResponse({
        requestBody,
        responseBody,
        signature: {
          text,
          signature,
          signing_address: wallet.address,
          signing_algo: 'ecdsa',
          signature_kind: 'provider_tee',
        },
        verifiedModelAttestation: attestation,
      }),
    ).toMatchObject({ scope: 'model_tee' });
  });

  test('rejects provider evidence when the raw request names an alias', async () => {
    const wallet = new ethers.Wallet(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const text = providerTeeSignatureText(
      'canonical-model',
      Buffer.from('{"model":"alias"}'),
      responseBody,
    );
    const signature = await wallet.signMessage(text);
    const attestation: VerifiedNearModelAttestation = {
      kind: 'near_model',
      signingAddress: wallet.address,
      signingAlgo: 'ecdsa',
      reportDataBinding: { kind: 'signer_nonce' },
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      appCompose: '{}',
      imageDigests: [],
      runtimeMeasurements: {},
      provenanceVerified: false,
    };

    expectVerificationFailure(
      () =>
        verifyProviderTeeResponse({
          requestBody: Buffer.from('{"model":"alias"}'),
          responseBody,
          signature: {
            text,
            signature,
            signing_address: wallet.address,
            signing_algo: 'ecdsa',
            signature_kind: 'provider_tee',
          },
          verifiedModelAttestation: attestation,
        }),
      {
        phase: 'signature',
        code: 'signature.payload_mismatch',
        details: { source: 'signed_payload', reason: 'text_mismatch' },
      },
    );
  });

  test('accepts an Ed25519 gateway signature but labels it gateway-only', () => {
    const keyPair = nacl.sign.keyPair.fromSeed(Buffer.alloc(32, 7));
    const text = gatewaySignatureText(requestBody, responseBody);
    const signature = Buffer.from(
      nacl.sign.detached(Buffer.from(text), keyPair.secretKey),
    ).toString('hex');
    const attestation: VerifiedGatewayAttestation = {
      kind: 'gateway',
      signingAddress: Buffer.from(keyPair.publicKey).toString('hex'),
      signingAlgo: 'ed25519',
      reportDataBinding: {
        kind: 'signer_peer_tls_nonce',
        tlsCertFingerprint: '11'.repeat(32),
      },
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      appCompose: '{}',
      imageDigests: [],
      runtimeMeasurements: {},
      provenanceVerified: false,
    };

    expect(
      verifyGatewayResponse({
        requestBody,
        responseBody,
        signature: {
          text,
          signature,
          signing_address: attestation.signingAddress,
          signing_algo: 'ed25519',
          signature_kind: 'gateway',
        },
        verifiedGatewayAttestation: attestation,
      }),
    ).toMatchObject({ scope: 'gateway' });
  });

  test('does not treat unavailable or missing signature kinds as evidence', () => {
    expectVerificationFailure(
      () =>
        requireKnownSignature({
          status: 'unavailable',
          unavailable: {
            error_code: 'SIGNATURE_UNSUPPORTED',
            message: 'unsupported',
          },
        }),
      {
        phase: 'signature',
        code: 'signature.unavailable',
        details: { providerErrorCode: 'SIGNATURE_UNSUPPORTED' },
      },
    );

    expectVerificationFailure(
      () =>
        requireKnownSignature({
          status: 'unknown_kind',
          signature: {
            text: 'x',
            signature: 'aa',
            signing_address: '11'.repeat(20),
            signing_algo: 'ecdsa',
          },
        }),
      {
        phase: 'signature',
        code: 'signature.unknown_kind',
      },
    );
  });
});
