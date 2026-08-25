import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
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
} from '../../src/types/verification';

const requestBody = Buffer.from('{"model":"canonical-model"}');
const responseBody = Buffer.from('data: hello\n\n');

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
      tlsCertFingerprint: '11'.repeat(32),
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
      tlsCertFingerprint: '11'.repeat(32),
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      appCompose: '{}',
      imageDigests: [],
      runtimeMeasurements: {},
      provenanceVerified: false,
    };

    expect(() =>
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
    ).toThrow('Signature text does not match');
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
      tlsCertFingerprint: '11'.repeat(32),
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
    expect(() =>
      requireKnownSignature({
        status: 'unavailable',
        unavailable: {
          error_code: 'SIGNATURE_UNSUPPORTED',
          message: 'unsupported',
        },
      }),
    ).toThrow('unavailable');

    expect(() =>
      requireKnownSignature({
        status: 'unknown_kind',
        signature: {
          text: 'x',
          signature: 'aa',
          signing_address: '11'.repeat(20),
          signing_algo: 'ecdsa',
        },
      }),
    ).toThrow('missing or unsupported');
  });
});
