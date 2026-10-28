import type {
  DeploymentProvenanceStatus,
  DeploymentVerifier,
  MeasuredDeployment,
} from '../types/verification';
import { wrapVerificationError } from '../utils/errors';

export async function runDeploymentVerifier(
  deployment: MeasuredDeployment,
  verifier: DeploymentVerifier | undefined,
): Promise<DeploymentProvenanceStatus> {
  if (verifier === undefined) return 'not_checked';
  try {
    await verifier(deployment);
    return 'verified';
  } catch (cause) {
    throw wrapVerificationError(
      { code: 'provenance.verification_failed' },
      cause,
    );
  }
}
