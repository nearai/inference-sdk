import { initContext } from '../context';
import { chatCompletions, fetchChatSignature } from '../common';
import { assertChatVerified, verifyChat } from '../../src';
import { ChatCompletionsResponse } from '../types';

describe('signature', () => {
  const context = initContext();

  let completions: ChatCompletionsResponse;

  beforeAll(async () => {
    completions = await chatCompletions({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      requestBody: {
        model: context.model,
        messages: [
          {
            role: 'user',
            content: 'Hello',
          },
        ],
        stream: true,
      },
    });
  });

  test('signature ecdsa', async () => {
    const signature = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      completions.id,
      context.model,
      'ecdsa',
    );

    expect(signature.signing_algo).toEqual('ecdsa');

    const verification = verifyChat(
      {
        requestBody: completions.requestBodyRaw,
        responseBody: completions.responseBodyRaw,
      },
      signature,
    );

    assertChatVerified(verification);
  });

  test('signature ed25519', async () => {
    const signature = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      completions.id,
      context.model,
      'ed25519',
    );

    expect(signature.signing_algo).toEqual('ed25519');

    const verification = verifyChat(
      {
        requestBody: completions.requestBodyRaw,
        responseBody: completions.responseBodyRaw,
      },
      signature,
    );

    assertChatVerified(verification);
  });
});
