import { JwtPayload } from '../types/common';
import { Buffer } from 'buffer';

export function decodeJwt(jwt: string): JwtPayload {
  const parts = jwt.split('.');

  if (parts.length !== 3) {
    throw Error('Invalid JWT format');
  }

  try {
    return JSON.parse(Buffer.from(parts[1], 'base64').toString());
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
  return Buffer.from(trimHexPrefix(hex), 'hex');
}

export function trimHexPrefix(hex: string): string {
  if (hex.startsWith('0x')) {
    return hex.slice(2);
  }
  return hex;
}
