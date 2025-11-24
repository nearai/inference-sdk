import { TcbInfo } from './attestation-common';
import { SigningAlgo } from './chat';

export type ModelAttestation = {
  signing_algo: SigningAlgo;
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  info: {
    tcb_info: string | TcbInfo;
  };
};
