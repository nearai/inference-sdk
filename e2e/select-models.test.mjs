import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, copyFile, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const model = (modelId, providerType, amount = 1, decisions = false) => ({
  modelId,
  inputCostPerToken: { amount, scale: 6 },
  outputCostPerToken: { amount, scale: 6 },
  metadata: {
    providerType,
    ownedBy: decisions ? 'typesafe' : 'example',
    attestationSupported: providerType === 'vllm',
    architecture: {
      inputModalities: ['text'],
      outputModalities: [decisions ? 'decisions' : 'text'],
    },
    supportedSamplingParameters: decisions ? [] : ['max_tokens'],
  },
});
const catalog = [
  model('near/b', 'vllm'), model('near/a', 'vllm'),
  model('chutes/a', 'chutes'), model('external/chat', 'external'),
  model('typesafe/expensive', 'external', 5, true),
  model('typesafe/cheap', 'external', 1, true),
];

async function runSelector(t, models = catalog, language = 'all', pageSize = 100) {
  const root = await mkdtemp(join(tmpdir(), 'sdk-model-selection-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'e2e'));
  await mkdir(join(root, 'js/e2e'), { recursive: true });
  await writeFile(join(root, 'js/e2e/systemone.test.ts'), '');
  await copyFile(new URL('./select-models.mjs', import.meta.url), join(root, 'e2e/select-models.mjs'));
  const requests = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    requests.push(url);
    const offset = Number(url.searchParams.get('offset'));
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ models: models.slice(offset, offset + pageSize), total: models.length }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const { stdout } = await exec(process.execPath, [join(root, 'e2e/select-models.mjs')], {
    env: {
      ...process.env,
      NEARAI_BASE_URL: `http://127.0.0.1:${server.address().port}/v1`,
      NEARAI_E2E_LANGUAGE: language,
    },
  });
  return { result: JSON.parse(stdout), requests };
}

test('selects Chat and System One from one catalog request', async t => {
  const { result, requests } = await runSelector(t);
  assert.deepEqual(result, {
    models: [
      { id: 'near/a', provider: 'near' }, { id: 'near/b', provider: 'near' },
      { id: 'chutes/a', provider: 'chutes' }, { id: 'external/chat', provider: 'external' },
    ],
    systemoneModel: 'typesafe/cheap',
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].pathname, '/v1/model/list');
});

test('loads each catalog page once for both selections', async t => {
  const { result, requests } = await runSelector(t, catalog, 'all', 2);
  assert.equal(result.systemoneModel, 'typesafe/cheap');
  assert.deepEqual(requests.map(url => url.searchParams.get('offset')), ['0', '2', '4']);
});

test('a language without System One tests needs only Chat models', async t => {
  const { result } = await runSelector(t, catalog.slice(0, 4), 'rust');
  assert.equal(result.models.length, 4);
  assert.equal(result.systemoneModel, '');
});

test('a language with System One tests requires a decision model', async t => {
  await assert.rejects(runSelector(t, catalog.slice(0, 4), 'javascript'), /Expected a hosted Jev decision model/);
});

test('all-language runs require a decision model when a suite is present', async t => {
  await assert.rejects(runSelector(t, catalog.slice(0, 4)), /Expected a hosted Jev decision model/);
});

test('decision models cannot satisfy Chat provider coverage', async t => {
  await assert.rejects(runSelector(t, catalog.filter(m => m.modelId !== 'external/chat')), /Expected 1 external Chat models/);
});

test('rejects an unknown language', async t => {
  await assert.rejects(runSelector(t, catalog, 'typo'), /Unknown E2E language/);
});
