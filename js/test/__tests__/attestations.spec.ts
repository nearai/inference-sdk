import { initContext } from '../context';
import { fetchAttestationReport, fetchDomainAttestation } from '../common';
import * as crypto from 'crypto';
import {
  verifyDomainAttestation,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';

describe('attestations', () => {
  const context = initContext();

  test('gateway attestation and model attestations', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      params: {
        model: context.model,
        requestNonce,
      },
    });

    await verifyGatewayAttestation(report.gateway_attestation, requestNonce);

    for (const modelAttestation of report.model_attestations ?? []) {
      await verifyModelAttestation(modelAttestation, requestNonce);
    }
  });

  test('domain attestation', async () => {
    const attestation = await fetchDomainAttestation(context.baseApiUrl);
    await verifyDomainAttestation(attestation);
  });
});
