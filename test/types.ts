export type Context = {
  apiUrl: string;
  apiKey: string;
  model: string;
}

export type ChatCompletionsParams = {
  apiUrl: string;
  apiKey: string;
  requestBody: {
    model: string;
    messages: {
      role: string;
      content: string;
    }[];
    [k: string]: unknown;
  }
}

export type ChatCompletionsResponse = {
  requestBodyRaw: Buffer,
  responseBodyRaw: Buffer,
  responseBody: {
    id: string;
  },
}
