import { TcbInfo } from './attestation-common';

export type ModelAttestation = {
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  info: {
    tcb_info: string | TcbInfo;
  };
};
