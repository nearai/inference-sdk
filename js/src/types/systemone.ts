import type * as v from 'valibot';
import type { SystemOneResponseSchema } from '../schemas';

/** Text or structured JSON passed through to the decision model. */
export type SystemOneContent = string | object;

/** JSON image data referenced by its key in the request's assets map. */
export type SystemOneImageAsset = {
  readonly type?: 'image';
  readonly format: 'png' | 'jpg' | 'jpeg';
  readonly data_base64: string;
};

export type SystemOneQuestion<
  Choices extends Readonly<
    Record<keyof Choices, SystemOneContent | null>
  > = Readonly<Record<string, SystemOneContent | null>>,
> =
  | {
      readonly type: 'noul';
      readonly instructions: SystemOneContent;
      readonly criteria?: {
        readonly true?: SystemOneContent;
        readonly false?: SystemOneContent;
      };
    }
  | {
      readonly type: 'choice';
      readonly instructions: SystemOneContent;
      readonly criteria: Choices;
    }
  | {
      readonly type: 'score';
      readonly instructions: SystemOneContent;
      readonly criteria: readonly SystemOneContent[];
    }
  | {
      readonly type: 'box';
      readonly instructions: SystemOneContent;
      readonly criteria?: never;
    };

// Distribute over question unions so explicitly annotated generic questions
// retain the known keys of each choice variant.
type CheckedSystemOneQuestion<Question> = Question extends {
  readonly criteria: infer Choices extends object;
}
  ? SystemOneQuestion<Readonly<Record<keyof Choices, SystemOneContent | null>>>
  : SystemOneQuestion;

/** Validate the named questions without requiring a string index signature. */
export type SystemOneQuestions<Questions> = {
  readonly [Name in keyof Questions as Name]: CheckedSystemOneQuestion<
    Questions[Name]
  >;
};

/** Text or structured context for a decision. */
export type SystemOneRequest<
  Questions extends object & SystemOneQuestions<Questions> = Readonly<
    Record<string, SystemOneQuestion>
  >,
> = {
  readonly model: string;
  readonly state: SystemOneContent;
  readonly questions: Questions;
  readonly assets?: Readonly<Record<string, SystemOneImageAsset>>;
};

export type SystemOneResponse = v.InferOutput<typeof SystemOneResponseSchema>;
export type SystemOneAnswer = SystemOneResponse['answers'][string];
export type SystemOneBoxCoordinates = Extract<
  SystemOneAnswer,
  { type: 'box' }
>['box'];

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
  readonly create: <
    const Questions extends object & SystemOneQuestions<Questions>,
  >(
    request: SystemOneRequest<Questions>,
    options?: SystemOneRequestOptions,
  ) => Promise<SystemOneResult>;
};
