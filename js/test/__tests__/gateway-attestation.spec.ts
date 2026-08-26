import { Buffer } from 'node:buffer';
import { verifyGatewayAttestation } from '../../src';
import type { GatewayAttestation } from '../../src';
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

describe('gateway attestation verification', () => {
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
      reportDataBinding: {
        kind: 'signer_peer_tls_nonce',
        tlsCertFingerprint: tlsFingerprint,
      },
    });
  });

  test('accepts an OutOfDate gateway TCB status by default', async () => {
    const quote = createQuote({ tcbStatus: 'OutOfDate' });
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        expectedNonce: nonce,
        peerTlsCertFingerprint: tlsFingerprint,
        quoteVerifier: { verify: async () => quote },
      }),
    ).resolves.toMatchObject({ tcbStatus: 'OutOfDate' });
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
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.tls_fingerprint_mismatch',
        details: { source: 'peer_tls_connection' },
      },
    });
  });

  test('requires a TLS fingerprint on gateway evidence', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({ tls_cert_fingerprint: null }),
        expectedNonce: nonce,
        peerTlsCertFingerprint: tlsFingerprint,
        quoteVerifier: { verify: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.tls_fingerprint_missing',
        details: { target: 'gateway' },
      },
    });
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
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'advertised_report_data' },
      },
    });
  });

  test('does not treat an empty gateway report_data field as absent', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({ report_data: '' }),
        expectedNonce: nonce,
        peerTlsCertFingerprint: tlsFingerprint,
        quoteVerifier: { verify: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_invalid',
        details: {
          source: 'advertised_report_data',
          reason: 'invalid_hex',
          expectedBytes: 64,
        },
      },
    });
  });
});
