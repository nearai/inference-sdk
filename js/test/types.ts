import { SigningAlgo } from '../src';

export type Context = {
  apiDomain: string;
  apiUrl: string;
  apiKey: string;
  model: string;
};

export type FetchAttestationReportParams = {
  apiUrl: string;
  apiKey: string;
  params: {
    model: string;
    requestNonce: string;
    signingAlgo: SigningAlgo;
  };
};

export type FetchChatSignatureParams = {
  apiUrl: string;
  apiKey: string;
  params: {
    chatId: string;
    model: string;
    signingAlgo: SigningAlgo;
  };
};

export type ChatCompletionsParams = {
  apiUrl: string;
  apiKey: string;
  requestBody: {
    model: string;
    messages: {
      role: string;
      content: string;
    }[];
    stream?: boolean;
    [k: string]: unknown;
  };
};

export type ChatCompletionsResponse = {
  id: string;
  requestBodyRaw: Buffer;
  responseBodyRaw: Buffer;
};
