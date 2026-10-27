import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { normalizeSystemOneRequest } from '../src/core/systemone-assets';

const png = readFileSync(
  resolve(__dirname, '../../test-fixtures/systemone/rectangle.png'),
);
const asset = { format: 'png', data_base64: png.toString('base64') };
const part = {
  type: 'image_url',
  image_url: { url: `data:image/png;base64,${asset.data_base64}` },
};
const encode = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value));

test('converts megabyte base64 image data', async () => {
  const data = Buffer.concat([png, Buffer.alloc(1024 * 1024)]).toString(
    'base64',
  );
  const result = await normalizeSystemOneRequest(
    encode({
      state: 'photo',
      assets: { photo: { format: 'png', data_base64: data } },
    }),
    new Headers({ 'content-type': 'application/json' }),
  );
  expect(result.parsed).toEqual({
    state: {
      type: 'image_url',
      image_url: { url: `data:image/png;base64,${data}` },
    },
  });
});

test('base64 assets expand content values while keeping keys and other fields', async () => {
  const headers = new Headers({
    'content-type': 'application/json',
    digest: 'old-body',
  });
  const request = {
    model: 'a+b',
    state: { 'a+b': ['a+b', 'before a+b and a+b after'] },
    questions: {
      'a+b': {
        type: 'noul',
        instructions: { nested: 'a+b' },
        criteria: { true: 'a+b', false: null },
        future: 'a+b',
      },
      choice: {
        type: 'choice',
        instructions: 'Pick',
        criteria: { 'a+b': 'a+b' },
      },
      score: { type: 'score', instructions: 'Rate', criteria: ['a+b', null] },
    },
    assets: { 'a+b': asset },
    metadata: 'a+b',
  };
  const normalized = await normalizeSystemOneRequest(encode(request), headers);
  expect(JSON.parse(new TextDecoder().decode(normalized.body))).toEqual({
    model: 'a+b',
    state: { 'a+b': [part, ['before ', part, ' and ', part, ' after']] },
    questions: {
      'a+b': {
        type: 'noul',
        instructions: { nested: part },
        criteria: { true: part, false: null },
        future: 'a+b',
      },
      choice: {
        type: 'choice',
        instructions: 'Pick',
        criteria: { 'a+b': part },
      },
      score: { type: 'score', instructions: 'Rate', criteria: [part, null] },
    },
    metadata: 'a+b',
  });
  expect(headers.has('digest')).toBe(false);
});

async function multipart(request: unknown, files: [string, Blob][] = []) {
  const form = new FormData();
  form.append(
    'request',
    new Blob([JSON.stringify(request)], { type: 'application/json' }),
    'request.json',
  );
  for (const [name, file] of files) form.append(name, file, name);
  const http = new Request('https://gateway.test/v1/systemone', {
    method: 'POST',
    body: form,
  });
  return normalizeSystemOneRequest(
    new Uint8Array(await http.arrayBuffer()),
    http.headers,
  );
}

test('multipart prefers file bytes and detects JPEG without a MIME type', async () => {
  const jpeg = new Uint8Array([255, 216, 255, 224]);
  const result = await multipart(
    {
      state: 'photo',
      assets: { photo: { part: 'upload', data_base64: 'ignored' } },
    },
    [['upload', new Blob([jpeg])]],
  );
  expect(result.parsed).toEqual({
    state: {
      type: 'image_url',
      image_url: { url: 'data:image/jpeg;base64,/9j/4A==' },
    },
  });
});

test.each([
  { state: 'photo', assets: { photo: { ...asset, data_base64: '!!!' } } },
  {
    state: 'photo',
    assets: { photo: { format: 'png', data_base64: 'bm90LWltYWdl' } },
  },
  { state: 'text', assets: { photo: asset } },
  { state: 'photo', assets: { photo: { part: 'missing' } } },
])(
  'rejects assets that cannot be faithfully converted: %j',
  async (request) => {
    await expect(
      normalizeSystemOneRequest(
        encode(request),
        new Headers({ 'content-type': 'application/json' }),
      ),
    ).rejects.toMatchObject({ failure: { code: 'api.invalid_input' } });
  },
);

test.each(['duplicate', 'unused', 'shared'])(
  'rejects %s multipart file parts',
  async (fault) => {
    const file = new Blob([png], { type: 'image/png' });
    const request = {
      state: ['photo', 'other'],
      assets: {
        photo: { part: 'upload' },
        ...(fault === 'shared' ? { other: { part: 'upload' } } : {}),
      },
    };
    const files: [string, Blob][] = [['upload', file]];
    if (fault !== 'shared')
      files.push([fault === 'duplicate' ? 'upload' : 'unused', file]);
    await expect(multipart(request, files)).rejects.toMatchObject({
      failure: { code: 'api.invalid_input' },
    });
  },
);
