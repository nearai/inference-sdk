import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

// Shared by all SDK suites. Discovery uses only the public catalog, not API keys.
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

  const price = (model) =>
    model.inputCostPerToken.amount / 10 ** model.inputCostPerToken.scale +
    model.outputCostPerToken.amount / 10 ** model.outputCostPerToken.scale;

  let systemoneModel = '';
  if (needsSystemOne) {
    // Hosted Jev cases verify Gateway receipts.
    const decisions = models.filter(({ metadata }) =>
      metadata.ownedBy === 'typesafe' &&
      metadata.providerType === 'external' &&
      !metadata.attestationSupported &&
      metadata.architecture?.outputModalities?.includes('decisions'),
    );
    decisions.sort(
      (a, b) => price(a) - price(b) || a.modelId.localeCompare(b.modelId),
    );
    assert.ok(decisions.length > 0, 'Expected a hosted Jev decision model');
    systemoneModel = decisions[0].modelId;
  }

  const chatModels = models.filter(({ metadata }) => {
    const architecture = metadata.architecture;
    const parameters = metadata.supportedSamplingParameters ?? [];
    // Exclude embeddings, images, audio, decisions, rerankers and privacy filters.
    // Older Chat entries may omit architecture but still list token parameters.
    return (
      (!architecture ||
        (architecture.inputModalities.includes('text') &&
          architecture.outputModalities.includes('text'))) &&
      (parameters.includes('max_tokens') ||
        parameters.includes('max_completion_tokens'))
    );
  });

  // Prefer non-reasoning models for the short output budget, then cheaper
  // representatives. Canonical IDs break ties without depending on catalog order.
  const reasoning = (model) =>
    Number(model.metadata.supportedFeatures?.includes('reasoning') ?? false);
  chatModels.sort(
    (a, b) =>
      reasoning(a) - reasoning(b) || price(a) - price(b) ||
      a.modelId.localeCompare(b.modelId),
  );
  const selected = [];
  const coverage = [['near', 2], ['chutes', 1], ['external', 1]];
  for (const [provider, count] of coverage) {
    const candidates = chatModels.filter(({ metadata }) =>
      provider === 'near'
        ? metadata.providerType === 'vllm' && metadata.attestationSupported
        : metadata.providerType === provider,
    );
    assert.ok(
      candidates.length >= count,
      `Expected ${count} ${provider} Chat models`,
    );
    selected.push(
      ...candidates.slice(0, count).map(({ modelId }) => ({
        id: modelId,
        provider,
      })),
    );
  }
  console.log(JSON.stringify({ models: selected, systemoneModel }));
}

await main();
