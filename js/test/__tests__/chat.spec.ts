import { initContext } from '../context';
import {
  chatCompletions,
  fetchAttestationReport,
  fetchChatSignature,
  generateRequestNonce,
  sleep,
} from '../common';
import { SigningAlgo, verifyChat, verifySigningAddress } from '../../src';
import { ChatCompletionsResponse, Context } from '../types';

describe('chat', () => {
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

    await sleep(5 * 1000); // Waiting for signature preparation
  });

  test('chat signature ecdsa', async () => {
    await testChatSignature(context, completions, 'ecdsa');
  });

  test('chat signature ed25519', async () => {
    await testChatSignature(context, completions, 'ed25519');
  });
});

async function testChatSignature(
  context: Context,
  completions: ChatCompletionsResponse,
  signingAlgo: SigningAlgo,
) {
  const signature = await fetchChatSignature({
    apiUrl: context.apiUrl,
    apiKey: context.apiKey,
    params: {
      chatId: completions.id,
      model: context.model,
      signingAlgo,
    },
  });

  expect(signature.signing_algo).toEqual(signingAlgo);

  verifyChat(
    {
      requestBody: completions.requestBodyRaw,
      responseBody: completions.responseBodyRaw,
    },
    signature,
  );

  const report = await fetchAttestationReport({
    apiUrl: context.apiUrl,
    apiKey: context.apiKey,
    params: {
      model: context.model,
      requestNonce: generateRequestNonce(),
      signingAlgo,
    },
  });

  verifySigningAddress(signature, report.model_attestations ?? []);
}
