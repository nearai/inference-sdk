import * as v from 'valibot';
import {
  SecureChatCompletionResponseSchema,
  SecureChatCompletionStreamChunkSchema,
} from '../schemas';
import type {
  SecureChatCompletionRequest,
  SecureChatCompletionResponse,
  SecureChatCompletionStreamChunk,
  SecureChatJsonObject,
} from '../types/secure-client';
import {
  ApiError,
  isApiError,
  isVerificationError,
  VerificationError,
} from '../utils/errors';
import {
  decryptE2eeText,
  encryptE2eeText,
  type E2eeClientKeyPair,
  type E2eeModelKey,
} from './e2ee';

export type ParseE2eeChatResponseParams = {
  readonly body: unknown;
};

export type ParseE2eeChatStreamChunkParams = {
  readonly chunk: unknown;
};

export type EncryptE2eeChatRequestParams = {
  readonly body: SecureChatCompletionRequest;
  readonly modelKey: E2eeModelKey;
};

export type EncryptedE2eeChatRequest = {
  readonly body: SecureChatCompletionRequest;
};

export type DecryptE2eeChatResponseParams = {
  readonly body: SecureChatCompletionResponse;
  readonly clientKeyPair: E2eeClientKeyPair;
};

export type DecryptE2eeChatStreamChunkParams = {
  readonly chunk: SecureChatCompletionStreamChunk;
  readonly clientKeyPair: E2eeClientKeyPair;
};

export type CreateE2eeChatSseTransformParams = {
  readonly clientKeyPair: E2eeClientKeyPair;
};

/** Parse an encrypted non-streaming Chat response without leaking a ValiError. */
export function parseE2eeChatResponse({
  body,
}: ParseE2eeChatResponseParams): SecureChatCompletionResponse {
  const parsed = v.safeParse(SecureChatCompletionResponseSchema, body);
  if (!parsed.success) {
    throw invalidResponse({
      path: 'Chat Completions response',
      expected: 'an encrypted Chat Completions response',
      actual: 'invalid',
    });
  }
  return parsed.output;
}

/** Parse one Chat SSE JSON record without leaking a ValiError. */
export function parseE2eeChatStreamChunk({
  chunk,
}: ParseE2eeChatStreamChunkParams): SecureChatCompletionStreamChunk {
  const parsed = v.safeParse(SecureChatCompletionStreamChunkSchema, chunk);
  if (!parsed.success) {
    throw invalidResponse({
      path: 'Chat Completions stream chunk',
      expected: 'a JSON Chat Completions stream chunk',
      actual: 'invalid',
    });
  }
  return parsed.output;
}

/**
 * Encrypt protocol-defined request fields without mutating the caller's
 * object. Other Chat JSON is preserved for the Gateway and model to handle.
 *
 * E2EE requests always opt into the protocol's all-fields extension. That
 * extension is intentionally selective: it enables additional documented
 * fields but does not turn arbitrary JSON into ciphertext.
 */
export function encryptE2eeChatRequest({
  body,
  modelKey,
}: EncryptE2eeChatRequestParams): EncryptedE2eeChatRequest {
  return {
    body: encryptRequestBody({ body, modelKey }),
  };
}

/** Decrypt a parsed, complete Chat Completions response. */
export function decryptE2eeChatResponse({
  body,
  clientKeyPair,
}: DecryptE2eeChatResponseParams): SecureChatCompletionResponse {
  const choices = asJsonArray(body.choices);
  if (choices === undefined) {
    return { ...body };
  }
  return {
    ...body,
    choices: choices.map((choice, choiceIndex) =>
      decryptResponseChoice({
        choice,
        clientKeyPair,
        path: `choices[${choiceIndex}]`,
      }),
    ),
  };
}

/** Decrypt one parsed Chat Completions SSE JSON event. */
export function decryptE2eeChatStreamChunk({
  chunk,
  clientKeyPair,
}: DecryptE2eeChatStreamChunkParams): SecureChatCompletionStreamChunk {
  const choices = asJsonArray(chunk.choices);
  if (choices === undefined) {
    return { ...chunk };
  }
  return {
    ...chunk,
    choices: choices.map((choice, choiceIndex) =>
      decryptStreamChoice({
        choice,
        clientKeyPair,
        path: `choices[${choiceIndex}]`,
      }),
    ),
  };
}

/**
 * Create a byte-safe SSE transform for an encrypted Chat Completions stream.
 *
 * It keeps incomplete UTF-8 and incomplete SSE records buffered, preserves
 * comments/control records and `[DONE]`, and only reserializes `data:` records
 * containing Chat Completions chunks.
 */
export function createE2eeChatSseTransform({
  clientKeyPair,
}: CreateE2eeChatSseTransformParams): TransformStream<Uint8Array, Uint8Array> {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const encoder = new TextEncoder();
  let pending = '';

  return new TransformStream({
    transform(chunk, controller) {
      try {
        pending += decoder.decode(chunk, { stream: true });
        const complete = takeCompleteSseRecords(pending);
        pending = complete.pending;
        for (const record of complete.records) {
          controller.enqueue(
            encoder.encode(
              transformSseRecord({
                record: record.value,
                separator: record.separator,
                clientKeyPair,
              }),
            ),
          );
        }
      } catch (cause) {
        throw asSseResponseError(cause);
      }
    },
    flush(controller) {
      try {
        pending += decoder.decode();
        if (pending.length > 0) {
          controller.enqueue(
            encoder.encode(
              transformSseRecord({
                record: pending,
                separator: '',
                clientKeyPair,
              }),
            ),
          );
        }
      } catch (cause) {
        throw asSseResponseError(cause);
      }
    },
  });
}

type EncryptRequestBodyParams = {
  readonly body: SecureChatCompletionRequest;
  readonly modelKey: E2eeModelKey;
};

function encryptRequestBody({
  body,
  modelKey,
}: EncryptRequestBodyParams): SecureChatCompletionRequest {
  const encrypted: SecureChatJsonObject = { ...body };
  const messages = asJsonArray(body.messages);
  if (messages !== undefined) {
    encrypted.messages = messages.map((message) => {
      const record = asJsonObject(message);
      return record === undefined
        ? message
        : encryptRequestMessage({
            message: record,
            modelKey,
          });
    });
  }

  const tools = asJsonArray(body.tools);
  if (tools !== undefined) {
    encrypted.tools = encryptTools({ tools, modelKey });
  }

  const toolChoice = asJsonObject(body.tool_choice);
  if (toolChoice !== undefined) {
    encrypted.tool_choice = encryptToolChoice({
      toolChoice,
      modelKey,
    });
  }

  const functionCall = asJsonObject(body.function_call);
  if (functionCall !== undefined) {
    encrypted.function_call = encryptFunctionCall({
      functionCall,
      modelKey,
      encryptArguments: false,
    });
  }

  return encrypted as SecureChatCompletionRequest;
}

type EncryptRequestMessageParams = {
  readonly message: SecureChatJsonObject;
  readonly modelKey: E2eeModelKey;
};

function encryptRequestMessage({
  message,
  modelKey,
}: EncryptRequestMessageParams): SecureChatJsonObject {
  const encrypted: SecureChatJsonObject = { ...message };
  const content = message.content;
  if (typeof content === 'string') {
    encrypted.content = encryptText({
      plaintext: content,
      modelKey,
    });
  } else if (Array.isArray(content)) {
    encrypted.content = encryptText({
      plaintext: JSON.stringify(content),
      modelKey,
    });
  }
  encryptStringField({
    source: message,
    target: encrypted,
    field: 'reasoning_content',
    modelKey,
  });
  encryptStringField({
    source: message,
    target: encrypted,
    field: 'reasoning',
    modelKey,
  });

  const audio = asJsonObject(message.audio);
  if (audio !== undefined) {
    encrypted.audio = encryptAudio({ audio, modelKey });
  }
  encryptStringField({
    source: message,
    target: encrypted,
    field: 'name',
    modelKey,
  });
  encryptStringField({
    source: message,
    target: encrypted,
    field: 'refusal',
    modelKey,
  });

  const toolCalls = asJsonArray(message.tool_calls);
  if (toolCalls !== undefined) {
    encrypted.tool_calls = encryptFunctionToolCalls({
      toolCalls,
      modelKey,
    });
  }

  const functionCall = asJsonObject(message.function_call);
  if (functionCall !== undefined) {
    encrypted.function_call = encryptFunctionCall({
      functionCall,
      modelKey,
      encryptArguments: true,
    });
  }
  return encrypted;
}

type EncryptAudioParams = {
  readonly audio: SecureChatJsonObject;
  readonly modelKey: E2eeModelKey;
};

function encryptAudio({
  audio,
  modelKey,
}: EncryptAudioParams): SecureChatJsonObject {
  const encrypted: SecureChatJsonObject = { ...audio };
  encryptStringField({
    source: audio,
    target: encrypted,
    field: 'data',
    modelKey,
  });
  return encrypted;
}

type EncryptToolsParams = {
  readonly tools: readonly unknown[];
  readonly modelKey: E2eeModelKey;
};

function encryptTools({ tools, modelKey }: EncryptToolsParams): unknown[] {
  return tools.map((tool) => {
    const record = asJsonObject(tool);
    if (record === undefined) {
      return tool;
    }
    const functionDefinition = asJsonObject(record.function);
    if (functionDefinition === undefined) {
      return { ...record };
    }
    const encryptedFunction: SecureChatJsonObject = { ...functionDefinition };
    encryptStringField({
      source: functionDefinition,
      target: encryptedFunction,
      field: 'name',
      modelKey,
    });
    encryptStringField({
      source: functionDefinition,
      target: encryptedFunction,
      field: 'description',
      modelKey,
    });
    if (functionDefinition.parameters !== undefined) {
      encryptedFunction.parameters = encryptText({
        plaintext: JSON.stringify(functionDefinition.parameters),
        modelKey,
      });
    }
    return { ...record, function: encryptedFunction };
  });
}

type EncryptToolChoiceParams = {
  readonly toolChoice: SecureChatJsonObject;
  readonly modelKey: E2eeModelKey;
};

function encryptToolChoice({
  toolChoice,
  modelKey,
}: EncryptToolChoiceParams): SecureChatJsonObject {
  const functionDefinition = asJsonObject(toolChoice.function);
  if (functionDefinition === undefined) {
    return { ...toolChoice };
  }
  const encryptedFunction: SecureChatJsonObject = { ...functionDefinition };
  encryptStringField({
    source: functionDefinition,
    target: encryptedFunction,
    field: 'name',
    modelKey,
  });
  return { ...toolChoice, function: encryptedFunction };
}

type EncryptFunctionToolCallsParams = {
  readonly toolCalls: readonly unknown[];
  readonly modelKey: E2eeModelKey;
};

function encryptFunctionToolCalls({
  toolCalls,
  modelKey,
}: EncryptFunctionToolCallsParams): unknown[] {
  return toolCalls.map((toolCall) => {
    const record = asJsonObject(toolCall);
    const functionCall = asJsonObject(record?.function);
    if (record === undefined || functionCall === undefined) {
      return toolCall;
    }
    return {
      ...record,
      function: encryptFunctionCall({
        functionCall,
        modelKey,
        encryptArguments: true,
      }),
    };
  });
}

type EncryptFunctionCallParams = {
  readonly functionCall: SecureChatJsonObject;
  readonly modelKey: E2eeModelKey;
  readonly encryptArguments: boolean;
};

function encryptFunctionCall({
  functionCall,
  modelKey,
  encryptArguments,
}: EncryptFunctionCallParams): SecureChatJsonObject {
  const encrypted: SecureChatJsonObject = { ...functionCall };
  encryptStringField({
    source: functionCall,
    target: encrypted,
    field: 'name',
    modelKey,
  });
  if (encryptArguments) {
    encryptStringField({
      source: functionCall,
      target: encrypted,
      field: 'arguments',
      modelKey,
    });
  }
  return encrypted;
}

type EncryptStringFieldParams = {
  readonly source: SecureChatJsonObject;
  readonly target: SecureChatJsonObject;
  readonly field: string;
  readonly modelKey: E2eeModelKey;
};

function encryptStringField({
  source,
  target,
  field,
  modelKey,
}: EncryptStringFieldParams): void {
  const value = source[field];
  if (typeof value === 'string') {
    target[field] = encryptText({ plaintext: value, modelKey });
  }
}

type EncryptTextParams = {
  readonly plaintext: string;
  readonly modelKey: E2eeModelKey;
};

function encryptText({ plaintext, modelKey }: EncryptTextParams): string {
  return encryptE2eeText({
    plaintext,
    modelKey,
  });
}

type DecryptResponseChoiceParams = {
  readonly choice: unknown;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptResponseChoice({
  choice,
  clientKeyPair,
  path,
}: DecryptResponseChoiceParams): unknown {
  const record = asJsonObject(choice);
  if (record === undefined) {
    return choice;
  }
  const decrypted: SecureChatJsonObject = { ...record };
  const message = asJsonObject(record.message);
  if (message !== undefined) {
    decrypted.message = decryptResponseMessage({
      message,
      clientKeyPair,
      path: `${path}.message`,
    });
  }
  const logprobs = asJsonObject(record.logprobs);
  if (logprobs !== undefined) {
    decrypted.logprobs = decryptLogprobs({
      logprobs,
      clientKeyPair,
      path: `${path}.logprobs`,
    });
  }
  return decrypted;
}

type DecryptStreamChoiceParams = {
  readonly choice: unknown;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptStreamChoice({
  choice,
  clientKeyPair,
  path,
}: DecryptStreamChoiceParams): unknown {
  const record = asJsonObject(choice);
  if (record === undefined) {
    return choice;
  }
  const decrypted: SecureChatJsonObject = { ...record };
  const delta = asJsonObject(record.delta);
  if (delta !== undefined) {
    decrypted.delta = decryptStreamDelta({
      delta,
      clientKeyPair,
      path: `${path}.delta`,
    });
  }
  const logprobs = asJsonObject(record.logprobs);
  if (logprobs !== undefined) {
    decrypted.logprobs = decryptLogprobs({
      logprobs,
      clientKeyPair,
      path: `${path}.logprobs`,
    });
  }
  return decrypted;
}

type DecryptResponseMessageParams = {
  readonly message: SecureChatJsonObject;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptResponseMessage({
  message,
  clientKeyPair,
  path,
}: DecryptResponseMessageParams): SecureChatJsonObject {
  const decrypted: SecureChatJsonObject = { ...message };
  const content = message.content;
  if (typeof content === 'string') {
    decrypted.content = decryptText({
      ciphertext: content,
      clientKeyPair,
      path: `${path}.content`,
    });
  } else if (Array.isArray(content)) {
    decrypted.content = decryptContentParts({
      parts: content,
      clientKeyPair,
      path: `${path}.content`,
    });
  }
  decryptStringField({
    source: message,
    target: decrypted,
    field: 'reasoning_content',
    clientKeyPair,
    path,
  });
  decryptStringField({
    source: message,
    target: decrypted,
    field: 'reasoning',
    clientKeyPair,
    path,
  });
  decryptStringField({
    source: message,
    target: decrypted,
    field: 'refusal',
    clientKeyPair,
    path,
  });

  const audio = asJsonObject(message.audio);
  if (audio !== undefined) {
    decrypted.audio = decryptAudio({ audio, clientKeyPair, path });
  }
  const toolCalls = asJsonArray(message.tool_calls);
  if (toolCalls !== undefined) {
    decrypted.tool_calls = decryptFunctionToolCalls({
      toolCalls,
      clientKeyPair,
      path: `${path}.tool_calls`,
    });
  }
  const functionCall = asJsonObject(message.function_call);
  if (functionCall !== undefined) {
    decrypted.function_call = decryptFunctionCall({
      functionCall,
      clientKeyPair,
      path: `${path}.function_call`,
    });
  }
  return decrypted;
}

type DecryptStreamDeltaParams = {
  readonly delta: SecureChatJsonObject;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptStreamDelta({
  delta,
  clientKeyPair,
  path,
}: DecryptStreamDeltaParams): SecureChatJsonObject {
  const decrypted = decryptResponseMessage({
    message: delta,
    clientKeyPair,
    path,
  });
  const toolResult = asJsonObject(delta.nearai_tool_result);
  if (toolResult !== undefined) {
    const decryptedToolResult: SecureChatJsonObject = { ...toolResult };
    decryptStringField({
      source: toolResult,
      target: decryptedToolResult,
      field: 'output',
      clientKeyPair,
      path: `${path}.nearai_tool_result`,
    });
    decrypted.nearai_tool_result = decryptedToolResult;
  }
  return decrypted;
}

type DecryptContentPartsParams = {
  readonly parts: readonly unknown[];
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptContentParts({
  parts,
  clientKeyPair,
  path,
}: DecryptContentPartsParams): unknown[] {
  return parts.map((part, index) => {
    const record = asJsonObject(part);
    if (record === undefined) {
      return part;
    }
    const decrypted: SecureChatJsonObject = { ...record };
    decryptStringField({
      source: record,
      target: decrypted,
      field: 'text',
      clientKeyPair,
      path: `${path}[${index}]`,
    });
    return decrypted;
  });
}

type DecryptAudioParams = {
  readonly audio: SecureChatJsonObject;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptAudio({
  audio,
  clientKeyPair,
  path,
}: DecryptAudioParams): SecureChatJsonObject {
  const decrypted: SecureChatJsonObject = { ...audio };
  decryptStringField({
    source: audio,
    target: decrypted,
    field: 'data',
    clientKeyPair,
    path: `${path}.audio`,
  });
  return decrypted;
}

type DecryptLogprobsParams = {
  readonly logprobs: SecureChatJsonObject;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptLogprobs({
  logprobs,
  clientKeyPair,
  path,
}: DecryptLogprobsParams): SecureChatJsonObject {
  const decrypted: SecureChatJsonObject = { ...logprobs };
  for (const field of ['content', 'refusal']) {
    const entries = asJsonArray(logprobs[field]);
    if (entries !== undefined) {
      decrypted[field] = decryptLogprobsEntries({
        entries,
        clientKeyPair,
        path: `${path}.${field}`,
      });
    }
  }
  return decrypted;
}

type DecryptLogprobsEntriesParams = {
  readonly entries: readonly unknown[];
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptLogprobsEntries({
  entries,
  clientKeyPair,
  path,
}: DecryptLogprobsEntriesParams): unknown[] {
  return entries.map((entry, index) => {
    const record = asJsonObject(entry);
    if (record === undefined) {
      return entry;
    }
    const decrypted: SecureChatJsonObject = { ...record };
    decryptStringField({
      source: record,
      target: decrypted,
      field: 'token',
      clientKeyPair,
      path: `${path}[${index}]`,
    });
    decryptJsonField({
      source: record,
      target: decrypted,
      field: 'bytes',
      clientKeyPair,
      path: `${path}[${index}]`,
    });
    const topLogprobs = asJsonArray(record.top_logprobs);
    if (topLogprobs !== undefined) {
      decrypted.top_logprobs = decryptLogprobsEntries({
        entries: topLogprobs,
        clientKeyPair,
        path: `${path}[${index}].top_logprobs`,
      });
    }
    return decrypted;
  });
}

type DecryptFunctionToolCallsParams = {
  readonly toolCalls: readonly unknown[];
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptFunctionToolCalls({
  toolCalls,
  clientKeyPair,
  path,
}: DecryptFunctionToolCallsParams): unknown[] {
  return toolCalls.map((toolCall, index) => {
    const record = asJsonObject(toolCall);
    const functionCall = asJsonObject(record?.function);
    if (record === undefined || functionCall === undefined) {
      return toolCall;
    }
    return {
      ...record,
      function: decryptFunctionCall({
        functionCall,
        clientKeyPair,
        path: `${path}[${index}].function`,
      }),
    };
  });
}

type DecryptFunctionCallParams = {
  readonly functionCall: SecureChatJsonObject;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptFunctionCall({
  functionCall,
  clientKeyPair,
  path,
}: DecryptFunctionCallParams): SecureChatJsonObject {
  const decrypted: SecureChatJsonObject = { ...functionCall };
  decryptStringField({
    source: functionCall,
    target: decrypted,
    field: 'name',
    clientKeyPair,
    path,
  });
  decryptStringField({
    source: functionCall,
    target: decrypted,
    field: 'arguments',
    clientKeyPair,
    path,
  });
  return decrypted;
}

type DecryptStringFieldParams = {
  readonly source: SecureChatJsonObject;
  readonly target: SecureChatJsonObject;
  readonly field: string;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptStringField({
  source,
  target,
  field,
  clientKeyPair,
  path,
}: DecryptStringFieldParams): void {
  const value = source[field];
  if (typeof value === 'string') {
    target[field] = decryptText({
      ciphertext: value,
      clientKeyPair,
      path: `${path}.${field}`,
    });
  }
}

type DecryptJsonFieldParams = {
  readonly source: SecureChatJsonObject;
  readonly target: SecureChatJsonObject;
  readonly field: string;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptJsonField({
  source,
  target,
  field,
  clientKeyPair,
  path,
}: DecryptJsonFieldParams): void {
  const value = source[field];
  if (typeof value !== 'string') {
    return;
  }
  const fieldPath = `${path}.${field}`;
  const plaintext = decryptText({
    ciphertext: value,
    clientKeyPair,
    path: fieldPath,
  });
  try {
    target[field] = JSON.parse(plaintext);
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'e2ee.decryption_failed',
        details: { field: fieldPath },
      },
      { cause },
    );
  }
}

type DecryptTextParams = {
  readonly ciphertext: string;
  readonly clientKeyPair: E2eeClientKeyPair;
  readonly path: string;
};

function decryptText({
  ciphertext,
  clientKeyPair,
  path,
}: DecryptTextParams): string {
  return decryptE2eeText({
    ciphertext,
    clientKeyPair,
    field: path,
  });
}

function asJsonObject(value: unknown): SecureChatJsonObject | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return undefined;
  }
  return value as SecureChatJsonObject;
}

function asJsonArray(value: unknown): readonly unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

type TransformSseRecordParams = {
  readonly record: string;
  readonly separator: string;
  readonly clientKeyPair: E2eeClientKeyPair;
};

function transformSseRecord({
  record,
  separator,
  clientKeyPair,
}: TransformSseRecordParams): string {
  const lines = splitSseLines(record);
  const dataLines = lines.filter(
    (line) => getSseData(line.content) !== undefined,
  );
  if (dataLines.length === 0) {
    return record + separator;
  }
  const data = dataLines
    .map((line) => getSseData(line.content) ?? '')
    .join('\n');
  if (data === '' || data === '[DONE]' || getSseEvent(lines) === 'error') {
    return record + separator;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.invalid_response',
        details: {
          path: 'Chat Completions SSE data',
          expected: 'a JSON event or [DONE]',
          actual: 'invalid JSON',
        },
      },
      { cause },
    );
  }
  const chunk = parseE2eeChatStreamChunk({ chunk: parsed });
  if (chunk.choices === undefined) {
    return record + separator;
  }
  const decrypted = decryptE2eeChatStreamChunk({
    chunk,
    clientKeyPair,
  });
  return replaceSseData(lines, JSON.stringify(decrypted)) + separator;
}

type SseLine = {
  readonly content: string;
  readonly ending: string;
};

function splitSseLines(value: string): SseLine[] {
  const lines: SseLine[] = [];
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '\n' && value[index] !== '\r') {
      continue;
    }
    const isCrLf = value[index] === '\r' && value[index + 1] === '\n';
    const ending = isCrLf ? '\r\n' : value[index];
    lines.push({ content: value.slice(start, index), ending });
    start = index + ending.length;
    if (isCrLf) {
      index += 1;
    }
  }
  if (start < value.length) {
    lines.push({ content: value.slice(start), ending: '' });
  }
  return lines;
}

function getSseData(line: string): string | undefined {
  if (line === 'data') {
    return '';
  }
  if (!line.startsWith('data:')) {
    return undefined;
  }
  const value = line.slice('data:'.length);
  return value.startsWith(' ') ? value.slice(1) : value;
}

function getSseEvent(lines: readonly SseLine[]): string | undefined {
  for (const line of lines) {
    if (line.content === 'event') {
      return '';
    }
    if (line.content.startsWith('event:')) {
      const value = line.content.slice('event:'.length);
      return value.startsWith(' ') ? value.slice(1) : value;
    }
  }
  return undefined;
}

function replaceSseData(lines: readonly SseLine[], serialized: string): string {
  let replaced = false;
  let output = '';
  for (const line of lines) {
    if (getSseData(line.content) === undefined) {
      output += line.content + line.ending;
      continue;
    }
    if (!replaced) {
      output += `data: ${serialized}${line.ending}`;
      replaced = true;
    }
  }
  return output;
}

type CompleteSseRecord = {
  readonly value: string;
  readonly separator: string;
};

function takeCompleteSseRecords(value: string): {
  readonly records: readonly CompleteSseRecord[];
  readonly pending: string;
} {
  const records: CompleteSseRecord[] = [];
  let remainder = value;
  while (true) {
    const boundary = findSseRecordBoundary(remainder);
    if (boundary === undefined) {
      return { records, pending: remainder };
    }
    records.push({
      value: remainder.slice(0, boundary.index),
      separator: boundary.separator,
    });
    remainder = remainder.slice(boundary.index + boundary.separator.length);
  }
}

function findSseRecordBoundary(
  value: string,
): { readonly index: number; readonly separator: string } | undefined {
  const match = /(?:\r\n|\n|\r)(?:\r\n|\n|\r)/.exec(value);
  if (match === null || match.index === undefined) {
    return undefined;
  }
  return { index: match.index, separator: match[0] };
}

function asSseResponseError(cause: unknown): ApiError | Error {
  if (isApiError(cause) || isVerificationError(cause)) {
    return cause;
  }
  return new ApiError(
    {
      code: 'api.invalid_response',
      details: {
        path: 'Chat Completions SSE response',
        expected: 'valid UTF-8 server-sent events',
        actual: 'invalid stream encoding',
      },
    },
    { cause },
  );
}

function invalidResponse(
  details: Extract<
    ApiError['failure'],
    { code: 'api.invalid_response' }
  >['details'],
): ApiError {
  return new ApiError({ code: 'api.invalid_response', details });
}
