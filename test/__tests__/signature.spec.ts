import { initContext } from '../context';
import { chatCompletions, fetchChatSignature } from '../common';
import { isChatVerified, verifyChat } from '../../src';

describe('signature', () => {
  const context = initContext();

  test('chat signature', async () => {
    const res = await chatCompletions({
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
      },
    });

    const signatureEcdsa = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      res.responseBody.id,
      context.model,
      'ecdsa',
    );

    const verificationEcdsa = verifyChat(
      {
        requestBody: res.requestBodyRaw,
        responseBody: res.responseBodyRaw,
      },
      signatureEcdsa,
    );

    expect(signatureEcdsa.signing_algo).toEqual('ecdsa');
    expect(isChatVerified(verificationEcdsa)).toBe(true);

    const signatureEd25519 = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      res.responseBody.id,
      context.model,
      'ed25519',
    );

    const verificationEd25519 = verifyChat(
      {
        requestBody: res.requestBodyRaw,
        responseBody: res.responseBodyRaw,
      },
      signatureEd25519,
    );

    expect(signatureEd25519.signing_algo).toEqual('ed25519');
    expect(isChatVerified(verificationEd25519)).toBe(true);
  });
});
