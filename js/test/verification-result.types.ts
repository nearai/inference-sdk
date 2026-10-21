// Both receipt IDs are available as strings; model attestations remain optional.
import type {
  VerifiedDirectCompletionResult,
  VerifiedGatewayCompletionResult,
  VerifiedModelCompletionResult,
} from '../src';

declare const gateway: VerifiedGatewayCompletionResult;
declare const model: Omit<VerifiedModelCompletionResult, 'attestations'>;
declare const direct: VerifiedDirectCompletionResult;

const modelResult: VerifiedModelCompletionResult = model;
const ids: string[] = [
  gateway.id,
  modelResult.id,
  direct.id,
  gateway.completionId,
  modelResult.completionId,
  direct.completionId,
];
void ids;
