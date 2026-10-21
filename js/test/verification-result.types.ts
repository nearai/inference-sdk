// Compile-only compatibility coverage for existing Playground-style adapters.
import type {
  VerifiedGatewayCompletionResult,
  VerifiedModelCompletionResult,
} from '../src/types/inference-client';
import type { VerifiedDirectCompletionResult } from '../src/types/direct-inference-client';

declare const gateway: Omit<VerifiedGatewayCompletionResult, 'id'>;
declare const model: Omit<VerifiedModelCompletionResult, 'id' | 'attestations'>;
declare const direct: Omit<VerifiedDirectCompletionResult, 'id'>;

const gatewayResult: VerifiedGatewayCompletionResult = gateway;
const modelResult: VerifiedModelCompletionResult = model;
const directResult: VerifiedDirectCompletionResult = direct;
const ids: string[] = [
  gatewayResult.completionId,
  modelResult.completionId,
  directResult.completionId,
];
void ids;
