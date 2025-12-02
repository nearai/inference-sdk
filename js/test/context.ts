import { Context } from './types';

export function initContext(): Context {
  const apiDomain = process.env.API_DOMAIN;
  if (!apiDomain) {
    throw Error('Missing env API_DOMAIN');
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
    apiDomain,
    apiUrl: `https://${apiDomain}/v1`,
    apiKey,
    model,
  };
}
