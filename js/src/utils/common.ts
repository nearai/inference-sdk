import { Buffer } from 'buffer';
import { INTEL_PCCS_API_URL_BROWSER, INTEL_PCCS_API_URL_NODE } from './consts';

export function decodeJwt(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');

  if (parts.length !== 3) {
    throw Error('Invalid JWT format');
  }

  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    throw Error('Invalid JWT payload');
  }
}

export function mapRecord<K extends string | number | symbol, V, U>(
  record: Record<K, V>,
  map: (key: K, value: V) => U,
): Record<K, U> {
  const result: Record<K, U> = {} as Record<K, U>;

  for (const key in record) {
    result[key] = map(key, record[key]);
  }

  return result;
}

export function hexToBuffer(hex: string): Buffer {
  const hexPattern = /^0x[0-9a-fA-F]+$|^[0-9a-fA-F]+$/;
  if (!hexPattern.test(hex)) {
    throw Error('Invalid hex string');
  }
  return Buffer.from(trimHexPrefix(hex), 'hex');
}

export function trimHexPrefix(hex: string): string {
  if (hex.startsWith('0x')) {
    return hex.slice(2);
  }
  return hex;
}

function isBrowser(): boolean {
  return typeof window !== 'undefined';
}

export function getIntelPccsApiUrl(): string {
  return isBrowser() ? INTEL_PCCS_API_URL_BROWSER : INTEL_PCCS_API_URL_NODE;
}
