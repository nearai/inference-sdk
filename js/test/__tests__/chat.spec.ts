import { initContext } from '../context';
import {
  chatCompletions,
  fetchAttestationReport,
  fetchChatSignature,
} from '../common';
import { verifyChat, verifySigningAddress } from '../../src';
import { ChatCompletionsResponse } from '../types';

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
  });

  test('chat signature ecdsa', async () => {
    const signature = await fetchChatSignature({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      params: {
        chatId: completions.id,
        model: context.model,
        signingAlgo: 'ecdsa',
      },
    });

    expect(signature.signing_algo).toEqual('ecdsa');

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
        signingAlgo: 'ecdsa',
      },
    });

    verifySigningAddress(signature.signing_address, report.model_attestations!);
  });

  test('chat signature ed25519', async () => {
    const signature = await fetchChatSignature({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      params: {
        chatId: completions.id,
        model: context.model,
        signingAlgo: 'ed25519',
      },
    });

    expect(signature.signing_algo).toEqual('ed25519');

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
        signingAlgo: 'ed25519',
      },
    });

    verifySigningAddress(signature.signing_address, report.model_attestations!);
  });
});
