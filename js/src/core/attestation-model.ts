import {
  ModelAttestation,
  VerifyModelAttestationConfig,
} from '../types/attestation-model';
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
  config: VerifyModelAttestationConfig,
) {
  const intelTdxVerificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdxForModel(
    intelTdxVerificationData,
    attestation.request_nonce,
    attestation.signing_address,
  );

  const nvidiaGpuVerificationData = await fetchNvidiaGpuVerificationData(
    attestation.nvidia_payload,
  );
  verifyNvidiaGpuForModel(nvidiaGpuVerificationData);

  if (config.imageNamesOfSigstoreHash.length > 0) {
    await verifyCompose(
      getComposeFromTcbInfo(attestation.info.tcb_info),
      config.imageNamesOfSigstoreHash,
    );
  }
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
    throw new VerificationError('NVIDIA GPU not verified');
  }
}
