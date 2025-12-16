import { SigningAlgo, TcbInfo } from './attestation-common';

export type ModelAttestation = {
  request_nonce: string;
  signing_algo: SigningAlgo;
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  info: {
    tcb_info: string | TcbInfo;
  };
};

export type ModelAttestationReport = {
  all_attestations: ModelAttestation[];
};
