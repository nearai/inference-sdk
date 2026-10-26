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
    ownedBy: decisions ? 'typesafe' : modelId === 'external/chat' ? 'openai' : modelId.startsWith('anthropic/') ? 'anthropic' : 'example',
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
  model('anthropic/text', 'external', 2),
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

test('selects Chat, Responses and System One from one catalog request', async t => {
  const { result, requests } = await runSelector(t, catalog.filter(m => m.metadata.ownedBy !== 'anthropic'));
  assert.deepEqual(result, [
    { id: 'near/a', provider: 'near', endpoint: 'chat' },
    { id: 'near/b', provider: 'near', endpoint: 'chat' },
    { id: 'chutes/a', provider: 'chutes', endpoint: 'chat' },
    { id: 'external/chat', provider: 'external', endpoint: 'chat' },
    { id: 'near/a', provider: 'near', endpoint: 'responses' },
    { id: 'external/chat', provider: 'external', endpoint: 'responses' },
    // { id: 'anthropic/text', provider: 'external', endpoint: 'messages' },
    { id: 'typesafe/cheap', provider: 'external', endpoint: 'systemone' },
  ]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].pathname, '/v1/model/list');
});

test('loads each catalog page once for all selections', async t => {
  const { result, requests } = await runSelector(t, catalog, 'all', 2);
  assert.equal(result.find(model => model.endpoint === 'systemone').id, 'typesafe/cheap');
  assert.deepEqual(requests.map(url => url.searchParams.get('offset')), ['0', '2', '4', '6']);
});

test('a language without System One tests needs Chat and Responses models', async t => {
  const { result } = await runSelector(t, catalog.filter(m => m.metadata.ownedBy !== 'typesafe'), 'rust');
  assert.equal(result.length, 6);
  assert.ok(result.every(model => model.endpoint !== 'systemone'));
});

test('a language with System One tests requires a decision model', async t => {
  await assert.rejects(runSelector(t, catalog.slice(0, 4), 'javascript'), /Expected a hosted Jev decision model/);
});

test('all-language runs require a decision model when a suite is present', async t => {
  await assert.rejects(runSelector(t, catalog.slice(0, 4)), /Expected a hosted Jev decision model/);
});

test('decision models cannot satisfy Chat provider coverage', async t => {
  await assert.rejects(runSelector(t, catalog.filter(m => m.metadata.providerType !== 'external' || m.metadata.ownedBy === 'typesafe')), /Expected 1 external Chat models/);
});

test('rejects an unknown language', async t => {
  await assert.rejects(runSelector(t, catalog, 'typo'), /Unknown E2E language/);
});

for (const separator of ['\n', '\r', '\r\n']) {
  test(`rejects line breaks in decision model IDs (${JSON.stringify(separator)})`, async t => {
    const models = [...catalog, model(`typesafe/cheap${separator}models=[]`, 'external', 0, true)];
    await assert.rejects(runSelector(t, models), /Model IDs must not contain line breaks/);
  });
}

test('Responses selects OpenAI even when another external provider is cheaper', async t => {
  const { result } = await runSelector(t, [...catalog, model('other/cheap', 'external', 0)]);
  assert.equal(result.find(m => m.endpoint === 'chat' && m.provider === 'external').id, 'other/cheap');
  assert.deepEqual(result.filter(m => m.endpoint === 'responses'), [
    { id: 'near/a', provider: 'near', endpoint: 'responses' },
    { id: 'external/chat', provider: 'external', endpoint: 'responses' },
  ]);
});

test('Responses requires OpenAI ownership rather than any external model', async t => {
  const models = catalog.map(m => m.modelId === 'external/chat'
    ? { ...m, metadata: { ...m.metadata, ownedBy: 'other' } }
    : m);
  await assert.rejects(runSelector(t, models), /Expected an OpenAI external text model for Responses/);
});

/* Messages support is deferred until a later release.

test('Messages selects Anthropic even when another external provider is cheaper', async t => {
  const { result } = await runSelector(t, [...catalog, model('other/cheap', 'external', 0)]);
  assert.deepEqual(result.filter(m => m.endpoint === 'messages'), [
    { id: 'anthropic/text', provider: 'external', endpoint: 'messages' },
  ]);
});

test('Messages selects the cheapest non-reasoning Anthropic text model across pages', async t => {
  const reasoning = model('anthropic/reasoning', 'external', 0);
  reasoning.metadata.supportedFeatures = ['reasoning'];
  const { result } = await runSelector(t, [...catalog, reasoning, model('anthropic/cheap', 'external', 1)], 'all', 2);
  assert.equal(result.find(m => m.endpoint === 'messages').id, 'anthropic/cheap');
});

test('Messages requires an Anthropic external text model', async t => {
  for (const metadata of [
    { ownedBy: 'other' },
    { attestationSupported: true },
    { architecture: { inputModalities: ['text'], outputModalities: ['image'] } },
  ]) {
    const models = catalog.map(m => m.modelId === 'anthropic/text'
      ? { ...m, metadata: { ...m.metadata, ...metadata } } : m);
    await assert.rejects(runSelector(t, models), /Expected an Anthropic external text model for Messages/);
  }
});
*/
