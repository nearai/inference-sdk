import { Buffer } from 'buffer';
import { INTEL_PCCS_API_URL_BROWSER, INTEL_PCCS_API_URL_NODE } from './consts';
import { VerificationError } from './errors';
import { inputError } from './input';

export function decodeJwt(jwt: string): Record<string, unknown> {
  if (typeof jwt !== 'string') {
    throw inputError('jwt', 'invalid_jwt');
  }
  const parts = jwt.split('.');

  if (parts.length !== 3) {
    throw inputError('jwt', 'invalid_jwt');
  }

  try {
    const payload: unknown = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString(),
    );
    if (
      payload === null ||
      typeof payload !== 'object' ||
      Array.isArray(payload)
    ) {
      throw inputError('jwt', 'invalid_jwt');
    }
    return payload as Record<string, unknown>;
  } catch {
    throw inputError('jwt', 'invalid_jwt');
  }
}

export function hexToBuffer(hex: string, field = 'hex'): Buffer {
  if (typeof hex !== 'string') {
    throw inputError(field, 'invalid_hex');
  }
  const normalized = trimHexPrefix(hex);
  if (
    normalized.length === 0 ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw inputError(field, 'invalid_hex');
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
  const bytes = hexToBuffer(value, label);
  if (bytes.length !== byteLength) {
    throw inputError(label, 'wrong_length', {
      expectedBytes: byteLength,
      actualBytes: bytes.length,
    });
  }
  return bytes;
}

export async function digest(
  algorithm: 'SHA-256' | 'SHA-384',
  value: Uint8Array,
): Promise<Buffer> {
  if (!globalThis.crypto?.subtle) {
    throw new VerificationError({
      phase: 'runtime',
      code: 'runtime.crypto_unavailable',
      details: { capability: 'subtle_digest' },
    });
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
    throw new VerificationError({
      phase: 'runtime',
      code: 'runtime.crypto_unavailable',
      details: { capability: 'secure_random' },
    });
  }
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return Buffer.from(nonce).toString('hex');
}

export function getIntelPccsApiUrl(): string {
  return hasNodeRuntime()
    ? INTEL_PCCS_API_URL_NODE
    : INTEL_PCCS_API_URL_BROWSER;
}

function hasNodeRuntime(): boolean {
  const runtime = globalThis as typeof globalThis & {
    process?: { versions?: { node?: unknown } };
  };
  return typeof runtime.process?.versions?.node === 'string';
}
