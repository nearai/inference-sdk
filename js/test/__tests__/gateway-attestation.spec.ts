import { verifyGatewayAttestation } from '../../src';
import { GatewayAttestation } from '../../src/types/attestation-gateway';
import {
  createNearModelAttestation,
  createQuote,
  nonce,
  tlsFingerprint,
} from '../fixtures';

function createGatewayAttestation(
  overrides: Partial<GatewayAttestation> = {},
): GatewayAttestation {
  const quote = createQuote();
  return {
    ...createNearModelAttestation(),
    report_data: Buffer.from(quote.reportData).toString('hex'),
    ...overrides,
  };
}

describe('verifyGatewayAttestation', () => {
  test('requires the gateway TLS peer fingerprint to match the quote binding', async () => {
    const quote = createQuote();
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      expectedNonce: nonce,
      peerTlsCertFingerprint: tlsFingerprint,
      quoteVerifier: { verify: async () => quote },
    });

    expect(result).toMatchObject({
      kind: 'gateway',
      tlsCertFingerprint: tlsFingerprint,
    });
  });

  test('rejects a gateway quote when the live TLS peer differs', async () => {
    const quote = createQuote();
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        expectedNonce: nonce,
        peerTlsCertFingerprint: '44'.repeat(32),
        quoteVerifier: { verify: async () => quote },
      }),
    ).rejects.toThrow('TLS fingerprint does not match the peer TLS connection');
  });

  test('rejects a gateway report_data field that contradicts the quote', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({
          report_data: 'ff'.repeat(64),
        }),
        expectedNonce: nonce,
        peerTlsCertFingerprint: tlsFingerprint,
        quoteVerifier: { verify: async () => createQuote() },
      }),
    ).rejects.toThrow('reported report_data does not match');
  });

  test('does not treat an empty gateway report_data field as absent', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({ report_data: '' }),
        expectedNonce: nonce,
        peerTlsCertFingerprint: tlsFingerprint,
        quoteVerifier: { verify: async () => createQuote() },
      }),
    ).rejects.toThrow('reported report_data must be a 64-byte hex string');
  });
});
