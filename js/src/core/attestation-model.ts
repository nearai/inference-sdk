import { ModelAttestation } from '../types/attestation-model';
import { checkIntelTdxVerification, verifyIntelTdx } from '../utils/intel';
import { checkNvidiaGpuVerification, verifyNvidiaGpu } from '../utils/nvidia';

export async function verifyModelAttestation(
  attestation: ModelAttestation,
  requestNonce: string,
  signingAddress: string,
) {
  const intelTdxVerification = await verifyIntelTdx(attestation.intel_quote);
  checkIntelTdxVerification(intelTdxVerification, requestNonce, signingAddress);

  const nvidiaGpuVerification = await verifyNvidiaGpu(
    attestation.nvidia_payload,
  );
  checkNvidiaGpuVerification(nvidiaGpuVerification);
}
