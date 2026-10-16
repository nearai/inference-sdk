// Compile-only API contract tests, included by typecheck:test.
import type {
  InferenceSystemOne,
  SystemOneQuestion,
  SystemOneRequest,
} from '../src/types/systemone';

interface Content {
  description: string;
}
interface Choices {
  billing: Content;
  support: null;
}
interface Questions {
  billing: { type: 'noul'; instructions: Content };
  team: { type: 'choice'; instructions: string; criteria: Choices };
  priority: { type: 'score'; instructions: string; criteria: string[] };
}
interface RequestDto {
  model: string;
  state: Content;
  questions: Questions;
}
declare const api: InferenceSystemOne;
declare const dto: RequestDto;
declare const choices: Choices;

void api.create(dto);
void api.create({
  model: 'm',
  state: 'state',
  questions: {
    team: { type: 'choice', instructions: 'Choose a team', criteria: choices },
  },
});

declare const dictionary: SystemOneRequest;
void api.create(dictionary);
declare const typed: SystemOneRequest<Questions>;
void api.create(typed);
const typedDto: SystemOneRequest<Questions> = dto;
void typedDto;

declare const invalidInstructions: {
  model: string;
  state: string;
  questions: { q: { type: 'noul'; instructions: number } };
};
// @ts-expect-error Numeric instructions are not valid content.
void api.create(invalidInstructions);
declare const missingInstructions: {
  model: string;
  state: string;
  questions: { q: { type: 'noul' } };
};
// @ts-expect-error Every question still requires instructions.
void api.create(missingInstructions);
declare const invalidCriteria: {
  model: string;
  state: string;
  questions: {
    q: { type: 'choice'; instructions: string; criteria: { bad: number } };
  };
};
// @ts-expect-error Choice descriptions must be text, structured content or null.
void api.create(invalidCriteria);
// @ts-expect-error Explicit generic question types must validate choice values too.
export type InvalidQuestion = SystemOneQuestion<{ bad: number }>;

// @ts-expect-error Questions must remain a map rather than a primitive.
void api.create({ model: 'm', state: 's', questions: 'invalid' });
declare const arrayQuestions: {
  model: string;
  state: string;
  questions: { type: 'noul'; instructions: string }[];
};
// @ts-expect-error Questions must remain a map rather than an array.
void api.create(arrayQuestions);
declare const arrayCriteria: {
  model: string;
  state: string;
  questions: {
    q: { type: 'choice'; instructions: string; criteria: string[] };
  };
};
// @ts-expect-error Choice criteria must remain a map rather than an array.
void api.create(arrayCriteria);
