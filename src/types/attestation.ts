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
  all_attestations?: AttestationReport[];
  info: {
    tcb_info:
      | string
      | {
          app_compose: string;
        };
  };
  signing_algo?: string;
  model_attestations?: AttestationReport[];
  gateway_attestation?: AttestationReport;
};
