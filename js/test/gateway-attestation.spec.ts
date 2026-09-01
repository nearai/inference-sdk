import { Buffer } from 'node:buffer';
import { verifyGatewayAttestation } from '../src';
import type { GatewayAttestation, MeasuredDeployment } from '../src';
import {
  appCompose,
  createGatewayTlsQuote,
  createModelQuote,
  createModelAttestation,
  nonce,
  tlsFingerprint,
} from './fixtures';

function createGatewayAttestation(
  overrides: Partial<GatewayAttestation> = {},
): GatewayAttestation {
  const quote = createGatewayTlsQuote();
  return {
    ...createModelAttestation(),
    reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
    ...overrides,
    spkiFingerprint: overrides.spkiFingerprint ?? tlsFingerprint,
  };
}

describe('gateway attestation verification', () => {
  test('binds gateway evidence to the caller-observed peer SPKI', async () => {
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce, spkiFingerprint: tlsFingerprint },
      verifiers: { quote: async () => createGatewayTlsQuote() },
    });

    expect(result).toMatchObject({
      tcbStatus: 'UpToDate',
      tlsBinding: { kind: 'attested', spkiFingerprint: tlsFingerprint },
      deploymentProvenance: 'not_checked',
    });
  });

  test('requires a peer observation by default', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce },
        verifiers: { quote: async () => createGatewayTlsQuote() },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.tls_binding_required' },
    });
  });

  test('uses signer-and-nonce binding when TLS verification is disabled', async () => {
    const quote = createModelQuote();
    const result = await verifyGatewayAttestation({
      attestation: {
        ...createModelAttestation(),
        reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
      },
      clientBinding: { nonce, spkiFingerprint: '44'.repeat(32) },
      policy: { verifyTlsBinding: false },
      verifiers: { quote: async () => quote },
    });

    expect(result.tlsBinding).toEqual({ kind: 'none' });
  });

  test('rejects gateway evidence when the live TLS peer differs', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce, spkiFingerprint: '44'.repeat(32) },
        verifiers: { quote: async () => createGatewayTlsQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.spki_fingerprint_mismatch',
      },
    });
  });

  test('rejects gateway report data that contradicts the verified quote', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({
          reportedQuoteData: 'ff'.repeat(64),
        }),
        clientBinding: { nonce, spkiFingerprint: tlsFingerprint },
        verifiers: { quote: async () => createGatewayTlsQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'reportedQuoteData' },
      },
    });
  });

  test('applies an explicit Gateway TCB policy', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce, spkiFingerprint: tlsFingerprint },
        policy: { acceptedTcbStatuses: ['OutOfDate'] },
        verifiers: { quote: async () => createGatewayTlsQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'policy.tcb_status_not_allowed',
        details: { actual: 'UpToDate', accepted: ['OutOfDate'] },
      },
    });
  });

  test('passes gateway measurements to a deployment verifier', async () => {
    const verifiedDeployments: MeasuredDeployment[] = [];
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce, spkiFingerprint: tlsFingerprint },
      verifiers: {
        quote: async () => createGatewayTlsQuote(),
        deployment: async (deployment) => {
          verifiedDeployments.push(deployment);
        },
      },
    });

    expect(verifiedDeployments).toEqual([
      { appCompose, runtimeMeasurements: {} },
    ]);
    expect(result.deploymentProvenance).toBe('verified');
  });
});
