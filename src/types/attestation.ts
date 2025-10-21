import { NvidiaGpuVerification } from './nvidia';
import { IntelTdxVerification } from './intel';

export type ModelAttestationVerification = {
  intel: IntelTdxVerification;
  nvidia: NvidiaGpuVerification;
};

export type ModelAttestation = {
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  request_nonce: string;
};

export type GatewayAttestationVerification = {
  intel: IntelTdxVerification;
};

export type GatewayAttestation = {
  intel_quote: string;
  request_nonce: string;
};
