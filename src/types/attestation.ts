import { NvidiaGpuVerification } from './nvidia';
import { IntelTdxVerification } from './intel';

export type AttestationReportVerification = {
  intel: IntelTdxVerification;
  nvidia: NvidiaGpuVerification;
};

export type AttestationReport = ModelAttestation & {
  model_attestations: ModelAttestation[];
  gateway_attestation?: GatewayAttestation;
};

export type ModelAttestation = {
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  request_nonce: string;
};

export type GatewayAttestation = {
  intel_quote: string;
  request_nonce: string;
};
