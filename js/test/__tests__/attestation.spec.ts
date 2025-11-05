import { initContext } from '../context';
import { fetchAttestationReport } from '../common';
import * as crypto from 'crypto';
import { verifyGatewayAttestation, verifyModelAttestation } from '../../src';

describe('attestation', () => {
  const context = initContext();

  test('gateway attestation and model attestations', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport(
      context.apiUrl,
      context.apiKey,
      context.model,
      requestNonce,
    );

    await verifyGatewayAttestation(report.gateway_attestation, requestNonce);

    for (const modelAttestation of report.model_attestations) {
      await verifyModelAttestation(
        modelAttestation,
        requestNonce,
        modelAttestation.signing_address,
      );
    }
  });
});
