// Both receipt IDs are available as strings.
import type {
  VerifiedDirectCompletionResult,
  VerifiedGatewayCompletionResult,
  VerifiedModelCompletionResult,
  VerifiedModelAttestation,
} from '../src';

declare const gateway: VerifiedGatewayCompletionResult;
declare const model: VerifiedModelCompletionResult;
declare const direct: VerifiedDirectCompletionResult;

const ids: string[] = [
  gateway.id,
  model.id,
  direct.id,
  gateway.completionId,
  model.completionId,
  direct.completionId,
];
void ids;

const modelReports: readonly VerifiedModelAttestation[] = model.attestations;
void modelReports;
