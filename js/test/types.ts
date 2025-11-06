export type Context = {
  baseApiUrl: string;
  apiUrl: string;
  apiKey: string;
  model: string;
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
