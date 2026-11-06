import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, copyFile, readFile, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const expected = [
  { id: 'z-ai/glm-5.3-flash', provider: 'near', endpoint: 'chat' },
  { id: 'Qwen/Qwen3.8-27B', provider: 'near', endpoint: 'chat' },
  { id: 'moonshotai/kimi-k3', provider: 'chutes', endpoint: 'chat' },
  { id: 'openai/gpt-6.1-sol', provider: 'external', endpoint: 'chat' },
  { id: 'z-ai/glm-5.3-flash', provider: 'near', endpoint: 'responses' },
  { id: 'openai/gpt-6.1-sol', provider: 'external', endpoint: 'responses' },
  { id: 'anthropic/claude-sonnet-5-5', provider: 'external', endpoint: 'messages' },
  { id: 'typesafe/jev-1.13', provider: 'external', endpoint: 'systemone' },
];
// Stable fixtures exercise the selector independently of the production IDs.
const fixtureConfig = [...new Set(expected.map(m => m.id))].map(id => ({
  id,
  provider: expected.find(m => m.id === id).provider,
  endpoints: expected.filter(m => m.id === id).map(m => m.endpoint),
}));
const model = (modelId, providerType, decisions = false) => ({
  modelId,
  inputCostPerToken: { amount: 1, scale: 6 },
  outputCostPerToken: { amount: 1, scale: 6 },
  metadata: {
    providerType,
    ownedBy: modelId.split('/')[0],
    attestationSupported: providerType === 'vllm',
    architecture: {
      inputModalities: ['text'],
      outputModalities: [decisions ? 'decisions' : 'text'],
    },
    supportedSamplingParameters: decisions ? [] : ['max_tokens'],
  },
});
const catalog = [
  model('z-ai/glm-5.3-flash', 'vllm'),
  model('Qwen/Qwen3.8-27B', 'vllm'),
  model('moonshotai/kimi-k3', 'chutes'),
  model('openai/gpt-6.1-sol', 'external'),
  model('anthropic/claude-sonnet-5-5', 'external'),
  model('typesafe/jev-1.13', 'external', true),
];
const alternatives = [
  model('near/alternative-a', 'vllm'),
  model('near/alternative-b', 'vllm'),
  model('chutes/alternative', 'chutes'),
  model('openai/alternative', 'external'),
  model('anthropic/alternative', 'external'),
  model('typesafe/alternative', 'external', true),
];
const systemOneSuites = {
  javascript: 'js/e2e/systemone.test.ts',
  python: 'py/e2e/test_systemone.py',
  rust: 'rs/e2e/systemone.rs',
  go: 'go/e2e/systemone_test.go',
};

async function runSelector(t, models = catalog, {
  language = 'all', pageSize = 100, suites = ['javascript'], config = fixtureConfig,
} = {}) {
  const root = await mkdtemp(join(tmpdir(), 'sdk-model-selection-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'e2e'));
  for (const sdk of suites) {
    const path = join(root, systemOneSuites[sdk]);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, '');
  }
  await copyFile(new URL('./select-models.mjs', import.meta.url), join(root, 'e2e/select-models.mjs'));
  await writeFile(join(root, 'e2e/models.json'), JSON.stringify(config));
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

function withMetadata(id, metadata) {
  return catalog.map(m => m.modelId === id
    ? { ...m, metadata: { ...m.metadata, ...metadata } } : m);
}

test('validates the fixed Chat, Responses, Messages and System One matrix', async t => {
  const { result, requests } = await runSelector(t);
  assert.deepEqual(result, expected);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].pathname, '/v1/model/list');
});

test('the production model configuration preserves required endpoint and provider coverage', async t => {
  const config = JSON.parse(await readFile(new URL('./models.json', import.meta.url), 'utf8'));
  const models = config.map(({ id, provider, endpoints }) =>
    model(id, provider === 'near' ? 'vllm' : provider, endpoints.includes('systemone')),
  );
  const { result } = await runSelector(t, models, { config });
  assert.deepEqual(result.map(({ endpoint, provider }) => `${endpoint}:${provider}`), [
    'chat:near', 'chat:near', 'chat:chutes', 'chat:external',
    'responses:near', 'responses:external', 'messages:external', 'systemone:external',
  ]);
  assert.equal(new Set(config.map(m => m.id)).size, config.length);
  assert.deepEqual(new Set(result.map(m => m.id)), new Set(config.map(m => m.id)));
});

test('catalog order, prices, reasoning flags and additional models do not change selection', async t => {
  const expensiveReasoningModels = catalog.map(m => ({
    ...m,
    inputCostPerToken: { amount: 999, scale: 6 },
    outputCostPerToken: { amount: 999, scale: 6 },
    metadata: { ...m.metadata, supportedFeatures: ['reasoning'] },
  }));
  const { result } = await runSelector(t, [...alternatives, ...expensiveReasoningModels].reverse());
  assert.deepEqual(result, expected);
});

test('selection does not require price metadata', async t => {
  const { result } = await runSelector(t, catalog.map(({ modelId, metadata }) => ({ modelId, metadata })));
  assert.deepEqual(result, expected);
});

test('loads each catalog page once to validate the fixed models', async t => {
  const { result, requests } = await runSelector(t, [...catalog].reverse(), { pageSize: 2 });
  assert.deepEqual(result, expected);
  assert.deepEqual(requests.map(url => url.searchParams.get('offset')), ['0', '2', '4']);
});

for (const { modelId } of catalog) {
  test(`fails when ${modelId} is missing instead of substituting another model`, async t => {
    const models = [...catalog.filter(m => m.modelId !== modelId), ...alternatives];
    await assert.rejects(runSelector(t, models), error =>
      error.stderr.includes(`Required E2E model is missing from the catalog: ${modelId}`),
    );
  });
}

for (const language of Object.keys(systemOneSuites)) {
  test(`${language} includes the fixed Jev model when its System One suite exists`, async t => {
    const { result } = await runSelector(t, catalog, { language, suites: [language] });
    assert.deepEqual(result, expected);
  });
}

test('a language without a System One suite does not require Jev', async t => {
  const models = catalog.filter(m => m.metadata.ownedBy !== 'typesafe');
  const { result } = await runSelector(t, models, { language: 'rust' });
  assert.deepEqual(result, expected.filter(m => m.endpoint !== 'systemone'));
});

test('all-language runs without any System One suites do not require Jev', async t => {
  const models = catalog.filter(m => m.metadata.ownedBy !== 'typesafe');
  const { result } = await runSelector(t, models, { suites: [] });
  assert.deepEqual(result, expected.filter(m => m.endpoint !== 'systemone'));
});

test('rejects an unknown language', async t => {
  await assert.rejects(runSelector(t, catalog, { language: 'typo' }), /Unknown E2E language/);
});

test('rejects provider changes that would alter the fixed coverage', async t => {
  for (const id of ['z-ai/glm-5.3-flash', 'moonshotai/kimi-k3', 'openai/gpt-6.1-sol']) {
    await assert.rejects(runSelector(t, withMetadata(id, { providerType: 'tinfoil' })), /Unexpected provider for E2E model/);
  }
});

test('requires NEAR attestation and external Gateway-only models', async t => {
  for (const [id, attestationSupported] of [
    ['z-ai/glm-5.3-flash', false],
    ['z-ai/glm-5.3-flash', 'false'],
    ['z-ai/glm-5.3-flash', 1],
    ['openai/gpt-6.1-sol', true],
    ['openai/gpt-6.1-sol', undefined],
    ['openai/gpt-6.1-sol', null],
    ['anthropic/claude-sonnet-5-5', true],
    ['typesafe/jev-1.13', true],
  ]) {
    await assert.rejects(runSelector(t, withMetadata(id, { attestationSupported })), /Unexpected attestation support for E2E model/);
  }
});

test('requires text generation capabilities for Chat, Responses and Messages', async t => {
  for (const metadata of [
    { architecture: { inputModalities: ['image'], outputModalities: ['text'] } },
    { architecture: { inputModalities: ['text'], outputModalities: ['decisions'] } },
    { supportedSamplingParameters: [] },
  ]) {
    await assert.rejects(runSelector(t, withMetadata('z-ai/glm-5.3-flash', metadata)), /Expected a text generation model/);
  }
});

test('accepts legacy text metadata and max_completion_tokens', async t => {
  const { result } = await runSelector(t, withMetadata('openai/gpt-6.1-sol', {
    architecture: undefined,
    supportedSamplingParameters: ['max_completion_tokens'],
  }));
  assert.deepEqual(result, expected);
});

test('requires OpenAI ownership for Responses and Anthropic ownership for Messages', async t => {
  await assert.rejects(runSelector(t, withMetadata('openai/gpt-6.1-sol', { ownedBy: 'other' })), /Expected an OpenAI Responses model/);
  await assert.rejects(runSelector(t, withMetadata('anthropic/claude-sonnet-5-5', { ownedBy: 'other' })), /Expected an Anthropic Messages model/);
});

test('requires a hosted Typesafe decision model for System One', async t => {
  for (const metadata of [
    { ownedBy: 'other' },
    { architecture: { inputModalities: ['text'], outputModalities: ['text'] } },
  ]) {
    await assert.rejects(runSelector(t, withMetadata('typesafe/jev-1.13', metadata)), /Expected a hosted Jev decision model/);
  }
});
