import type * as v from 'valibot';
import type {
  SystemOneRequestSchema,
  SystemOneResponseSchema,
} from '../core/systemone';
import type { VerifiedCompletionResult } from './inference-client';

/** Text or structured context for a decision. */
export type SystemOneRequest = v.InferOutput<typeof SystemOneRequestSchema>;
export type SystemOneQuestion = SystemOneRequest['questions'][string];
export type SystemOneResponse = v.InferOutput<typeof SystemOneResponseSchema>;
export type SystemOneAnswer = SystemOneResponse['answers'][string];

export type SystemOneRequestOptions = {
  readonly headers?: HeadersInit;
  readonly signal?: AbortSignal;
};

/** Unverified output plus byte-exact receipt verification. */
export type SystemOneResult = {
  readonly data: SystemOneResponse;
  /** X-Signature-Id, which may differ from the optional upstream data.id. */
  readonly signatureId: string;
  /** Verify the captured bytes, never a reserialized or caller-mutated data object. */
  readonly verify: () => Promise<VerifiedCompletionResult>;
};

export type InferenceSystemOne = {
  readonly create: (
    request: SystemOneRequest,
    options?: SystemOneRequestOptions,
  ) => Promise<SystemOneResult>;
};
