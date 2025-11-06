import { Context } from './types';

export function initContext(): Context {
  const baseApiUrl = process.env.BASE_API_URL;
  if (!baseApiUrl) {
    throw Error('Missing env API_URL');
  }

  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw Error('Missing env API_KEY');
  }

  const model = process.env.MODEL;
  if (!model) {
    throw Error('Missing env MODEL');
  }

  return {
    baseApiUrl,
    apiUrl: `${baseApiUrl}/v1`,
    apiKey,
    model,
  };
}
