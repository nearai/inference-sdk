import { Context } from './types';

export function initContext(): Context {
  const apiUrl = process.env.API_URL;
  if (!apiUrl) {
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
    apiUrl,
    apiKey,
    model,
  };
}
