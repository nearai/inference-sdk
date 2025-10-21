import { NvidiaGpuVerification } from './nvidia';
import { IntelTdxVerification } from './intel';

export type AttestationReportVerification = {
  intel: IntelTdxVerification;
  nvidia: NvidiaGpuVerification;
};

export type AttestationReport = {
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  request_nonce: string;
  all_attestations?: AttestationReport[];
  model_attestations?: AttestationReport[];
  gateway_attestation?: AttestationReport;
  signing_algo?: string;
  info?: {
    tcb_info:
      | string
      | {
          app_compose: string;
        };
  };
};
