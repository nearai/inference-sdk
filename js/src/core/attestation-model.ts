import { ModelAttestation } from '../types/attestation-model';
import { fetchIntelTdxVerificationData } from '../utils/intel';
import { fetchNvidiaGpuVerificationData } from '../utils/nvidia';
import {
  getComposeFromTcbInfo,
  verifyCompose,
  verifyIntelQuoteReportDataForAttestationReport,
} from './attestation-common';
import { IntelTdxVerificationData } from '../types/intel';
import { VerificationError } from '../utils/errors';
import { NvidiaGpuVerificationData } from '../types/nvidia';

export async function verifyModelAttestation(
  attestation: ModelAttestation,
  requestNonce: string,
  signingAddress: string,
) {
  const intelTdxVerificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdxForModel(
    intelTdxVerificationData,
    requestNonce,
    signingAddress,
  );

  const nvidiaGpuVerificationData = await fetchNvidiaGpuVerificationData(
    attestation.nvidia_payload,
  );
  verifyNvidiaGpuForModel(nvidiaGpuVerificationData);

  await verifyCompose(getComposeFromTcbInfo(attestation.info.tcb_info));
}

function verifyIntelTdxForModel(
  verificationData: IntelTdxVerificationData,
  requestNonce: string,
  signingAddress: string,
) {
  if (!verificationData.quote.verified) {
    throw new VerificationError('Intel quote not verified');
  }

  verifyIntelQuoteReportDataForAttestationReport(
    verificationData.quote.body.reportdata,
    requestNonce,
    signingAddress,
  );
}

function verifyNvidiaGpuForModel(verificationData: NvidiaGpuVerificationData) {
  const result = verificationData.JWT['x-nvidia-overall-att-result'];
  if (!result) {
    throw new VerificationError('Nvidia GPU not verified');
  }
}
