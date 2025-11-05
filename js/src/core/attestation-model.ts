import { ModelAttestation } from '../types/attestation-model';
import { verifyIntelTdx, fetchIntelTdxVerificationData } from '../utils/intel';
import {
  verifyNvidiaGpu,
  fetchNvidiaGpuVerificationData,
} from '../utils/nvidia';

export async function verifyModelAttestation(
  attestation: ModelAttestation,
  requestNonce: string,
  signingAddress: string,
) {
  const intelTdxVerificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  verifyIntelTdx(intelTdxVerificationData, requestNonce, signingAddress);

  const nvidiaGpuVerificationData = await fetchNvidiaGpuVerificationData(
    attestation.nvidia_payload,
  );
  verifyNvidiaGpu(nvidiaGpuVerificationData);
}
