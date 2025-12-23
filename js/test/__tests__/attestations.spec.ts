import { initContext } from '../context';
import {
  fetchAttestationReport,
  fetchDomainAttestation,
  generateRequestNonce,
} from '../common';
import {
  SigningAlgo,
  verifyDomainAttestation,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';
import { Context } from '../types';

const SIGSTORE_IMAGE_NAMES_FOR_GATEWAY_ATTESTATION: string[] = [
  'nearaidev/cloud-api',
];

const SIGSTORE_IMAGE_NAMES_FOR_MODEL_ATTESTATION: string[] = [
  // TODO: what should be verified?
];

const SIGSTORE_IMAGE_NAMES_FOR_DOMAIN_ATTESTATION: string[] = [
  'nearaidev/dstack-ingress-vpc',
];

describe('attestations', () => {
  const context = initContext();

  test('gateway attestation and model attestations ecdsa', async () => {
    await testGatewayAttestationAndModelAttestations(context, 'ecdsa');
  });

  test('gateway attestation and model attestations ed25519', async () => {
    await testGatewayAttestationAndModelAttestations(context, 'ed25519');
  });

  test('domain attestation', async () => {
    const attestation = await fetchDomainAttestation(context.apiDomain);
    await verifyDomainAttestation(attestation, {
      sigStoreImageNames: SIGSTORE_IMAGE_NAMES_FOR_DOMAIN_ATTESTATION,
    });
  });
});

async function testGatewayAttestationAndModelAttestations(
  context: Context,
  signingAlgo: SigningAlgo,
) {
  const requestNonce = generateRequestNonce();

  const report = await fetchAttestationReport({
    apiUrl: context.apiUrl,
    apiKey: context.apiKey,
    params: {
      model: context.model,
      requestNonce,
      signingAlgo,
    },
  });

  expect(report.gateway_attestation.request_nonce).toEqual(requestNonce);
  expect(report.gateway_attestation.signing_algo).toEqual(signingAlgo);

  await verifyGatewayAttestation(report.gateway_attestation, {
    domain: context.apiDomain,
    sigStoreImageNames: SIGSTORE_IMAGE_NAMES_FOR_GATEWAY_ATTESTATION,
  });

  for (const modelAttestation of report.model_attestations ?? []) {
    expect(modelAttestation.request_nonce).toEqual(requestNonce);
    expect(modelAttestation.signing_algo).toEqual(signingAlgo);

    await verifyModelAttestation(modelAttestation, {
      sigStoreImageNames: SIGSTORE_IMAGE_NAMES_FOR_MODEL_ATTESTATION,
    });
  }
}
