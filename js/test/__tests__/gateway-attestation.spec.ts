import { Buffer } from 'node:buffer';
import { verifyGatewayAttestation } from '../../src';
import type { GatewayAttestation } from '../../src';
import {
  createModelAttestation,
  createQuote,
  nonce,
  tlsFingerprint,
} from '../fixtures';

function createGatewayAttestation(
  overrides: Partial<GatewayAttestation> = {},
): GatewayAttestation {
  const quote = createQuote();
  return {
    ...createModelAttestation(),
    reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
    ...overrides,
  };
}

describe('gateway attestation verification', () => {
  test('binds gateway evidence to the caller-observed peer SPKI', async () => {
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      nonce,
      peerSpkiFingerprint: tlsFingerprint,
      verifiers: { quote: async () => createQuote() },
    });

    expect(result).toMatchObject({
      tcbStatus: 'UpToDate',
      tlsBinding: { kind: 'peer', spkiFingerprint: tlsFingerprint },
      deploymentProvenance: 'not_checked',
    });
    expect('gpuEvidence' in result).toBe(false);
  });

  test('rejects gateway evidence when the live TLS peer differs', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        nonce,
        peerSpkiFingerprint: '44'.repeat(32),
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.spki_fingerprint_mismatch',
        details: { source: 'peer_tls_connection' },
      },
    });
  });

  test('requires a declared SPKI fingerprint on gateway evidence', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({
          declaredSpkiFingerprint: null,
        }),
        nonce,
        peerSpkiFingerprint: tlsFingerprint,
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: { phase: 'binding', code: 'binding.spki_fingerprint_missing' },
    });
  });

  test('rejects gateway report data that contradicts the verified quote', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({
          reportedQuoteData: 'ff'.repeat(64),
        }),
        nonce,
        peerSpkiFingerprint: tlsFingerprint,
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'reportedQuoteData' },
      },
    });
  });
});
