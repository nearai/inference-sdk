import { GatewayAttestation } from './attestation-gateway';
import { ModelAttestation } from './attestation-model';

export type AttestationReport = {
  gateway_attestation: GatewayAttestation;
  model_attestations?: ModelAttestation[];
};
