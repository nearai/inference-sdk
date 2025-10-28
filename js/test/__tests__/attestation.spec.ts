import { initContext } from '../context';
import { fetchAttestationReport } from '../common';
import * as crypto from 'crypto';
import {
  assertGatewayAttestationVerified,
  assertModelAttestationVerified,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';

describe.skip('attestation', () => {
  const context = initContext();

  test('gateway attestation and model attestations', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport(
      context.apiUrl,
      context.apiKey,
      context.model,
      requestNonce,
    );

    const gatewayVerification = await verifyGatewayAttestation(
      report.gateway_attestation,
    );
    assertGatewayAttestationVerified(gatewayVerification, requestNonce);

    for (const modelAttestation of report.model_attestations) {
      const modelVerification = await verifyModelAttestation(modelAttestation);
      assertModelAttestationVerified(
        modelVerification,
        requestNonce,
        modelAttestation.signing_address,
      );
    }
  });
});
