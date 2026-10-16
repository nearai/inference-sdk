import assert from 'node:assert/strict';

// Shared by all SDK suites. Discovery uses only the public catalog, not API keys.
async function main() {
  const endpoint = process.argv[2] ?? 'chat';
  assert.ok(['chat', 'systemone'].includes(endpoint), 'Expected chat or systemone');
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

  if (endpoint === 'systemone') {
    // Hosted Jev provides Gateway receipts, not NEAR model-TEE evidence.
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
    console.log(decisions[0].modelId);
    return;
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
  console.log(JSON.stringify(selected));
}

await main();
