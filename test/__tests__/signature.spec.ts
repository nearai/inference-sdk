import { initContext } from '../context';
import {
  chatCompletions,
  fetchChatSignature,
} from '../common';
import {
  isChatVerified,
  verifyChat,
} from '../../src';

describe('signature', () => {
  const context = initContext();

  test('signature', async () => {
    const res = await chatCompletions({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      requestBody: {
        model: context.model,
        messages: [
          {
            role: 'user',
            content: 'Hello'
          }
        ]
      }
    });

    const signature = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      res.responseBody.id,
      context.model,
      'ecdsa',
    );

    const verification = verifyChat({
      requestBody: res.requestBodyRaw,
      responseBody: res.responseBodyRaw,
    }, signature);

    expect(
      isChatVerified(verification)
    ).toBe(true);
  })
});
