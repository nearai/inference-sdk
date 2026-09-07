import { Buffer } from 'buffer';
import { INTEL_PCCS_API_URL_BROWSER, INTEL_PCCS_API_URL_NODE } from './consts';
import { inputError } from './errors';

type RequireByteLengthParams = {
  value: string;
  byteLength: number;
  label: string;
};

export function hexToBuffer(hex: string, field = 'hex'): Buffer {
  const normalized = trimHexPrefix(hex);
  if (
    normalized.length === 0 ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw inputError({ field, reason: 'invalid_hex' });
  }
  return Buffer.from(normalized, 'hex');
}

export function trimHexPrefix(hex: string): string {
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    return hex.slice(2);
  }
  return hex;
}

export function requireByteLength({
  value,
  byteLength,
  label,
}: RequireByteLengthParams): Buffer {
  const bytes = hexToBuffer(value, label);
  if (bytes.length !== byteLength) {
    throw inputError({
      field: label,
      reason: 'wrong_length',
      details: {
        expectedBytes: byteLength,
        actualBytes: bytes.length,
      },
    });
  }
  return bytes;
}

export async function digest(
  algorithm: 'SHA-256' | 'SHA-384',
  value: Uint8Array,
): Promise<Buffer> {
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
