import { Buffer } from 'buffer';
import { INTEL_PCCS_API_URL_BROWSER, INTEL_PCCS_API_URL_NODE } from './consts';
import { VerificationError } from './errors';

export function decodeJwt(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');

  if (parts.length !== 3) {
    throw new VerificationError('Invalid JWT format');
  }

  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    throw new VerificationError('Invalid JWT payload');
  }
}

export function hexToBuffer(hex: string): Buffer {
  const normalized = trimHexPrefix(hex);
  if (
    normalized.length === 0 ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw new VerificationError('Invalid hex string');
  }
  return Buffer.from(normalized, 'hex');
}

export function trimHexPrefix(hex: string): string {
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    return hex.slice(2);
  }
  return hex;
}

export function normalizeHex(hex: string): string {
  return hexToBuffer(hex).toString('hex');
}

export function requireByteLength(
  value: string,
  byteLength: number,
  label: string,
): Buffer {
  const bytes = hexToBuffer(value);
  if (bytes.length !== byteLength) {
    throw new VerificationError(
      `${label} must be ${byteLength} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

export async function digest(
  algorithm: 'SHA-256' | 'SHA-384',
  value: Uint8Array,
): Promise<Buffer> {
  if (!globalThis.crypto?.subtle) {
    throw new VerificationError(
      'Web Crypto is unavailable; use a runtime with SubtleCrypto support',
    );
  }

  const bytes = value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;
  return Buffer.from(await globalThis.crypto.subtle.digest(algorithm, bytes));
}

export async function sha256(value: Uint8Array): Promise<Buffer> {
  return digest('SHA-256', value);
}

export async function sha384(value: Uint8Array): Promise<Buffer> {
  return digest('SHA-384', value);
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function generateNonce(): string {
  if (!globalThis.crypto?.getRandomValues) {
    throw new VerificationError(
      'Web Crypto is unavailable; cannot generate a secure nonce',
    );
  }
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return Buffer.from(nonce).toString('hex');
}

function isBrowser(): boolean {
  return typeof window !== 'undefined';
}

export function getIntelPccsApiUrl(): string {
  return isBrowser() ? INTEL_PCCS_API_URL_BROWSER : INTEL_PCCS_API_URL_NODE;
}
