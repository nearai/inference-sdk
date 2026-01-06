import { TcbInfo } from './attestation-common';

export type DomainAttestation = {
  intel_quote: string;
  domain: string;
  cert: string;
  acme_account: string;
  sha256sum: string;
  info: {
    tcb_info: string | TcbInfo;
  };
};

export type VerifyDomainAttestationConfig = {
  imageNamesOfSigstoreHash: string[];
};
