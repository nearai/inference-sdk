import type * as v from 'valibot';
import type { SystemOneResponseSchema } from '../schemas';

/** Text or structured JSON passed through to the decision model. */
export type SystemOneContent =
  | string
  | Record<string, unknown>
  | readonly unknown[];

export type SystemOneQuestion =
  | {
      readonly type: 'noul';
      readonly instructions?: SystemOneContent;
      readonly criteria?: {
        readonly true?: SystemOneContent;
        readonly false?: SystemOneContent;
      };
    }
  | {
      readonly type: 'choice';
      readonly instructions?: SystemOneContent;
      readonly criteria: Readonly<Record<string, SystemOneContent | null>>;
    }
  | {
      readonly type: 'score';
      readonly instructions?: SystemOneContent;
      readonly criteria: readonly SystemOneContent[];
    };

/** Text or structured context for a decision. */
export type SystemOneRequest = {
  readonly model: string;
  readonly state: SystemOneContent;
  readonly questions: Readonly<Record<string, SystemOneQuestion>>;
};

export type SystemOneResponse = v.InferOutput<typeof SystemOneResponseSchema>;
export type SystemOneAnswer = SystemOneResponse['answers'][string];

export type SystemOneRequestOptions = {
  readonly headers?: HeadersInit;
  readonly signal?: AbortSignal;
};

/** Unverified output; pass decisionId to client.verifyResponse() to verify it. */
export type SystemOneResult = {
  readonly data: SystemOneResponse;
  /** Generation ID from X-Generation-Id, used to retrieve and verify the signature. */
  readonly decisionId: string;
};

export type InferenceSystemOne = {
  readonly create: (
    request: SystemOneRequest,
    options?: SystemOneRequestOptions,
  ) => Promise<SystemOneResult>;
};
