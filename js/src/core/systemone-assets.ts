import { Buffer } from 'buffer';
import { ApiError } from '../utils/errors';

/** Normalize TypeSafe image uploads before the verified transport captures bytes. */
export async function normalizeSystemOneRequest(
  body: Uint8Array<ArrayBuffer>,
  headers: Headers,
): Promise<{ body: Uint8Array<ArrayBuffer>; parsed: unknown }> {
  const multipart =
    headers.get('content-type')?.split(';')[0].trim().toLowerCase() ===
    'multipart/form-data';
  const files = new Map<string, Blob>();
  let json = body;
  if (multipart) {
    let form: FormData;
    try {
      form = await new Response(body, { headers }).formData();
    } catch {
      throw invalidAssets('a valid multipart System One request');
    }
    const names = new Set<string>();
    for (const [name, value] of form) {
      if (!name || names.has(name) || (names.size === 0 && name !== 'request'))
        throw invalidAssets('unique multipart names, with request first');
      names.add(name);
      if (name === 'request') {
        json =
          typeof value === 'string'
            ? new TextEncoder().encode(value)
            : new Uint8Array(await value.arrayBuffer());
      } else {
        if (typeof value === 'string' || !imageContentTypes.has(value.type))
          throw invalidAssets('PNG or JPEG image file parts');
        files.set(name, value);
      }
    }
    if (!names.has('request'))
      throw invalidAssets('a multipart request JSON part');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(json));
  } catch {
    throw invalidAssets('a JSON System One request with a non-empty model');
  }
  const hasAssets = isObject(parsed) && parsed.assets != null;
  if (isObject(parsed) && hasAssets) {
    if (!isObject(parsed.assets)) throw invalidAssets('an image assets map');
    const images = new Map<string, unknown>();
    for (const [reference, asset] of Object.entries(parsed.assets)) {
      if (
        !reference.trim() ||
        !isObject(asset) ||
        (asset.type !== undefined && asset.type !== 'image')
      )
        throw invalidAssets('named image assets');
      let bytes: Uint8Array;
      if (asset.part != null) {
        const file =
          typeof asset.part === 'string' ? files.get(asset.part) : undefined;
        if (!file)
          throw invalidAssets('one existing file part per image asset');
        files.delete(asset.part as string);
        bytes = new Uint8Array(await file.arrayBuffer());
      } else {
        if (
          !['png', 'jpg', 'jpeg'].includes(String(asset.format)) ||
          typeof asset.data_base64 !== 'string' ||
          asset.data_base64.length % 4 !== 0 ||
          !/^[A-Za-z0-9+/]*={0,2}$/.test(asset.data_base64)
        )
          throw invalidAssets('PNG or JPEG assets with standard base64 data');
        bytes = Buffer.from(asset.data_base64, 'base64');
      }
      // The official SDK also accepts files without a MIME type. Detect it from
      // the bytes; leave image decoding, dimensions, and provider limits upstream.
      const mime = imageMime(bytes);
      images.set(reference, {
        type: 'image_url',
        image_url: {
          url: `data:${mime};base64,${Buffer.from(bytes).toString('base64')}`,
        },
      });
    }
    const used = new Set<string>();
    const references = [...images.keys()].sort((a, b) => b.length - a.length);
    const pattern = references.length
      ? new RegExp(
          references
            .map((ref) => ref.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
            .join('|'),
          'g',
        )
      : undefined;
    const replace = (value: unknown): unknown => {
      if (typeof value === 'string') {
        if (images.has(value)) {
          used.add(value);
          return images.get(value);
        }
        if (!pattern) return value;
        const parts: unknown[] = [];
        let end = 0;
        for (const match of value.matchAll(pattern)) {
          if (match.index > end) parts.push(value.slice(end, match.index));
          parts.push(images.get(match[0]));
          used.add(match[0]);
          end = match.index + match[0].length;
        }
        if (!parts.length) return value;
        if (end < value.length) parts.push(value.slice(end));
        return parts;
      }
      if (Array.isArray(value)) return value.map(replace);
      if (isObject(value))
        return Object.fromEntries(
          Object.entries(value).map(([key, item]) => [key, replace(item)]),
        );
      return value;
    };
    if ('state' in parsed) parsed.state = replace(parsed.state);
    if (isObject(parsed.questions)) {
      for (const question of Object.values(parsed.questions)) {
        if (!isObject(question)) continue;
        for (const field of ['instructions', 'criteria'])
          if (field in question) question[field] = replace(question[field]);
      }
    }
    if (used.size !== images.size)
      throw invalidAssets(
        'every image referenced in state, instructions, or criteria',
      );
    delete parsed.assets;
  }
  if (files.size) throw invalidAssets('one image asset per file part');
  if (!multipart && !hasAssets) return { body, parsed };
  for (const name of [
    'content-length',
    'content-encoding',
    'transfer-encoding',
    'trailer',
    'content-md5',
    'digest',
    'content-digest',
    'repr-digest',
  ])
    headers.delete(name);
  headers.set('content-type', 'application/json');
  return { body: new TextEncoder().encode(JSON.stringify(parsed)), parsed };
}

const imageContentTypes = new Set([
  '',
  'application/octet-stream',
  'image/png',
  'image/jpeg',
  'image/jpg',
]);

function imageMime(bytes: Uint8Array): string {
  if ([137, 80, 78, 71, 13, 10, 26, 10].every((byte, i) => bytes[i] === byte))
    return 'image/png';
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255)
    return 'image/jpeg';
  throw invalidAssets('PNG or JPEG image bytes');
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function invalidAssets(expected: string): ApiError {
  return new ApiError({
    code: 'api.invalid_input',
    details: { field: 'systemone', reason: 'unsupported_value', expected },
  });
}
