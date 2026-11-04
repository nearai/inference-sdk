import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import fixedModels from './models.json' with { type: 'json' };

async function main() {
  const language = process.env.NEARAI_E2E_LANGUAGE || 'all';
  const systemOneSuites = {
    javascript: '../js/e2e/systemone.test.ts',
    python: '../py/e2e/test_systemone.py',
    rust: '../rs/e2e/systemone.rs',
    go: '../go/e2e/systemone_test.go',
  };
  assert.ok(language === 'all' || Object.hasOwn(systemOneSuites, language), 'Unknown E2E language');
  const needsSystemOne = Object.entries(systemOneSuites).some(
    ([sdk, path]) => (language === 'all' || language === sdk) &&
      existsSync(new URL(path, import.meta.url)),
  );
  assert.ok(process.env.NEARAI_BASE_URL, 'NEARAI_BASE_URL is required');
  const baseUrl = `${process.env.NEARAI_BASE_URL.replace(/\/+$/, '')}/`;
  const models = [];
  for (let offset = 0; ; ) {
    const url = new URL('model/list', baseUrl);
    url.searchParams.set('limit', '100');
    url.searchParams.set('offset', String(offset));
    const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    assert.equal(response.status, 200, 'Model catalog request must succeed');
    const page = await response.json();
    assert.ok(Array.isArray(page.models), 'Expected a model catalog page');
    assert.ok(Number.isInteger(page.total), 'Expected a model catalog total');
    models.push(...page.models);
    offset += page.models.length;
    if (offset >= page.total) break;
    assert.ok(page.models.length > 0, 'Model catalog pagination made no progress');
  }

  const endpoints = ['chat', 'responses', 'messages', ...(needsSystemOne ? ['systemone'] : [])];
  const selected = endpoints.flatMap(endpoint =>
    fixedModels.filter(model => model.endpoints.includes(endpoint))
      .map(({ id, provider }) => ({ id, provider, endpoint })),
  );
  const catalog = new Map(models.map(model => [model.modelId, model]));
  for (const { id, provider, endpoint } of selected) {
    const model = catalog.get(id);
    assert.ok(model, `Required E2E model is missing from the catalog: ${id}`);
    const { metadata } = model;
    assert.equal(
      metadata.providerType,
      provider === 'near' ? 'vllm' : provider,
      `Unexpected provider for E2E model: ${id}`,
    );
    if (provider === 'near' || provider === 'external') {
      assert.equal(
        Boolean(metadata.attestationSupported),
        provider === 'near',
        `Unexpected attestation support for E2E model: ${id}`,
      );
    }

    if (endpoint === 'systemone') {
      // Hosted Jev cases verify Gateway receipts.
      assert.ok(
        metadata.ownedBy === 'typesafe' &&
        metadata.architecture?.outputModalities?.includes('decisions'),
        `Expected a hosted Jev decision model: ${id}`,
      );
      continue;
    }

    const architecture = metadata.architecture;
    const parameters = metadata.supportedSamplingParameters ?? [];
    // Older Chat entries may omit architecture but still list token parameters.
    assert.ok(
      (!architecture ||
        (architecture.inputModalities.includes('text') &&
          architecture.outputModalities.includes('text'))) &&
      (parameters.includes('max_tokens') ||
        parameters.includes('max_completion_tokens')),
      `Expected a text generation model: ${id}`,
    );
    if (endpoint === 'responses' && provider === 'external') {
      assert.equal(metadata.ownedBy, 'openai', `Expected an OpenAI Responses model: ${id}`);
    }
    if (endpoint === 'messages') {
      assert.equal(metadata.ownedBy, 'anthropic', `Expected an Anthropic Messages model: ${id}`);
    }
  }
  console.log(JSON.stringify(selected));
}

await main();
