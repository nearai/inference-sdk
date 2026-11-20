// Both receipt IDs are available as strings.
import type {
  VerifiedGatewayCompletionResult,
  VerifiedModelAttestation,
  VerifiedModelCompletionResult,
} from '../src';

declare const gateway: VerifiedGatewayCompletionResult;
declare const model: VerifiedModelCompletionResult;

const ids: string[] = [
  gateway.id,
  model.id,
  gateway.completionId,
  model.completionId,
];
void ids;

const modelReports: readonly VerifiedModelAttestation[] = model.attestations;
void modelReports;
