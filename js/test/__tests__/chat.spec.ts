import { initContext } from '../context';
import {
  chatCompletions,
  fetchAttestationReport,
  fetchChatSignature,
} from '../common';
import { verifyChat, verifySigningAddress } from '../../src';
import { ChatCompletionsResponse } from '../types';
import crypto from 'crypto';

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
    const signature = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      completions.id,
      context.model,
      'ecdsa',
    );

    expect(signature.signing_algo).toEqual('ecdsa');

    verifyChat(
      {
        requestBody: completions.requestBodyRaw,
        responseBody: completions.responseBodyRaw,
      },
      signature,
    );

    const report = await fetchAttestationReport(
      context.apiUrl,
      context.apiKey,
      context.model,
      crypto.randomBytes(32).toString('hex'),
      'ecdsa',
    );

    verifySigningAddress(signature.signing_address, report.model_attestations);
  });

  test('chat signature ed25519', async () => {
    const signature = await fetchChatSignature(
      context.apiUrl,
      context.apiKey,
      completions.id,
      context.model,
      'ed25519',
    );

    expect(signature.signing_algo).toEqual('ed25519');

    verifyChat(
      {
        requestBody: completions.requestBodyRaw,
        responseBody: completions.responseBodyRaw,
      },
      signature,
    );

    const report = await fetchAttestationReport(
      context.apiUrl,
      context.apiKey,
      context.model,
      crypto.randomBytes(32).toString('hex'),
      'ed25519',
    );

    verifySigningAddress(signature.signing_address, report.model_attestations);
  });
});
