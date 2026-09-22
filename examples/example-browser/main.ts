import {
  AttestationClient,
  InferenceClient,
  createGpuEvidenceVerifier,
  isApiError,
  isVerificationError,
  verifyGatewayAttestation,
} from '@nearai/inference-sdk';
import './style.css';

const DEFAULT_BASE_URL = 'https://cloud-api.near.ai/v1';
const SIGNING_ALGO = 'ed25519';
const DEFAULT_MODEL = { id: 'z-ai/glm-5.3-flash', label: 'GLM 5.3 Flash' };

type ChatMessage = { role: 'user' | 'assistant'; content: string };
type Status = 'idle' | 'pending' | 'verified' | 'failed' | 'warning';
type SelectableModel = { id: string; label: string };
type CatalogModel = {
  modelId?: unknown;
  metadata?: {
    verifiable?: unknown;
    attestationSupported?: unknown;
    providerType?: unknown;
    isReady?: unknown;
    modelDisplayName?: unknown;
    architecture?: { inputModalities?: unknown; outputModalities?: unknown };
  };
};

const baseUrlInput = element<HTMLInputElement>('base-url');
const apiKeyInput = element<HTMLInputElement>('api-key');
const modelSelect = element<HTMLSelectElement>('model-select');
const promptInput = element<HTMLInputElement>('prompt');
const form = element<HTMLFormElement>('chat-form');
const sendButton = element<HTMLButtonElement>('send');
const messagesElement = element<HTMLDivElement>('messages');
const errorElement = element<HTMLParagraphElement>('error');
const history: ChatMessage[] = [];
const emptyState = element<HTMLElement>('empty-state').cloneNode(true);
let selectedModel: SelectableModel = DEFAULT_MODEL;
let availableModels: SelectableModel[] = [DEFAULT_MODEL];
let currentBaseUrl = DEFAULT_BASE_URL;
let catalogRequestId = 0;
let catalogLoading = false;
let isSending = false;
let endpointDirty = false;

// Keep one client per key and endpoint: verifyResponse(id) must run on the
// client that sent the request and captured its exact encrypted bytes.
let activeClient: { apiKey: string; baseUrl: string; client: InferenceClient } | undefined;

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing element: ${id}`);
  return value as T;
}

function setStatus(section: 'gateway' | 'model', status: Status, text: string, details: string): void {
  const label = element<HTMLElement>(`${section}-status`);
  label.className = `status ${status}`;
  label.textContent = text;
  element<HTMLElement>(`${section}-details`).textContent = details;
}

function addMessage(role: 'user' | 'assistant', content: string): {
  body: HTMLParagraphElement;
  receipt: HTMLParagraphElement;
} {
  document.getElementById('empty-state')?.remove();
  const card = document.createElement('article');
  card.className = `message ${role}`;
  const title = document.createElement('strong');
  title.textContent = role === 'user' ? 'You' : selectedModel.label;
  const body = document.createElement('p');
  body.textContent = content;
  const receipt = document.createElement('p');
  receipt.className = 'note';
  card.append(title, body, receipt);
  messagesElement.append(card);
  messagesElement.scrollTop = messagesElement.scrollHeight;
  return { body, receipt };
}

function resetConversation(): void {
  activeClient = undefined;
  history.length = 0;
  messagesElement.replaceChildren(emptyState.cloneNode(true));
  errorElement.textContent = '';
  setStatus('gateway', 'idle', 'Not checked', 'A fresh Gateway attestation is checked before each prompt.');
  setStatus('model', 'idle', 'Not checked', 'Model evidence and the encryption key are verified before Chat is sent.');
}

function normalizeBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error('Enter a valid Cloud API URL, including https://.');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('Use HTTPS for the Cloud API URL (HTTP is allowed only on localhost).');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('The Cloud API URL cannot contain credentials, query parameters, or a fragment.');
  }
  return url.href.replace(/\/+$/, '');
}

function updateSelectedModel(): void {
  element<HTMLElement>('model-id').textContent = selectedModel.id;
  element<HTMLElement>('model-avatar').textContent = selectedModel.id[0]?.toUpperCase() ?? 'M';
  promptInput.placeholder = `Message ${selectedModel.label}…`;
}

function selectableModel(value: unknown): SelectableModel | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const model = value as CatalogModel;
  const metadata = model.metadata;
  if (
    typeof model.modelId !== 'string' ||
    !metadata ||
    metadata.verifiable !== true ||
    metadata.attestationSupported !== true ||
    (typeof metadata.providerType !== 'string' || metadata.providerType.trim().toLowerCase() !== 'vllm') ||
    metadata.isReady !== true ||
    !Array.isArray(metadata.architecture?.inputModalities) ||
    !metadata.architecture.inputModalities.includes('text') ||
    !Array.isArray(metadata.architecture.outputModalities) ||
    !metadata.architecture.outputModalities.includes('text')
  ) return undefined;
  return {
    id: model.modelId,
    label: typeof metadata.modelDisplayName === 'string' && metadata.modelDisplayName.trim()
      ? metadata.modelDisplayName
      : model.modelId,
  };
}

async function loadModels(baseUrl: string): Promise<void> {
  const requestId = ++catalogRequestId;
  catalogLoading = true;
  sendButton.disabled = true;
  modelSelect.disabled = true;
  try {
    // Public catalog data; never send the API key to this request.
    const response = await fetch(`${baseUrl}/model/list?limit=500&offset=0`, {
      signal: AbortSignal.timeout(5000),
    });
    if (requestId !== catalogRequestId) return;
    if (!response.ok) throw new Error(`Model catalog returned HTTP ${response.status}`);
    const catalog: unknown = await response.json();
    if (requestId !== catalogRequestId) return;
    const entries = catalog && typeof catalog === 'object' && 'models' in catalog
      ? catalog.models
      : undefined;
    if (!Array.isArray(entries)) throw new Error('Model catalog response is invalid');
    const models = entries
      .map(selectableModel)
      .filter((model): model is SelectableModel => model !== undefined)
      .sort((a, b) => a.label.localeCompare(b.label));
    if (models.length === 0) throw new Error('No compatible Private TEE chat models are available');
    availableModels = models;
    modelSelect.replaceChildren(...models.map((model) => {
      const option = document.createElement('option');
      option.value = model.id;
      option.textContent = model.label;
      return option;
    }));
    const nextModel = models.find((model) => model.id === selectedModel.id) ?? models[0]!;
    if (nextModel.id !== selectedModel.id) resetConversation();
    selectedModel = nextModel;
    modelSelect.value = selectedModel.id;
    modelSelect.title = '';
    updateSelectedModel();
  } catch (error) {
    if (requestId !== catalogRequestId) return;
    // The built-in model remains usable; the SDK still verifies its evidence
    // before sending, so a catalog outage cannot bypass verification.
    modelSelect.title = `Could not load the model catalog (${describeError(error)}); using the default model.`;
  } finally {
    if (requestId === catalogRequestId) {
      catalogLoading = false;
      if (!isSending) {
        sendButton.disabled = false;
        modelSelect.disabled = false;
      }
    }
  }
}

async function switchEndpoint(baseUrl: string): Promise<void> {
  if (baseUrl === currentBaseUrl) return;
  currentBaseUrl = baseUrl;
  resetConversation();
  selectedModel = DEFAULT_MODEL;
  availableModels = [DEFAULT_MODEL];
  modelSelect.replaceChildren(new Option(DEFAULT_MODEL.label, DEFAULT_MODEL.id));
  modelSelect.value = DEFAULT_MODEL.id;
  updateSelectedModel();
  await loadModels(baseUrl);
}

modelSelect.addEventListener('change', () => {
  const nextModel = availableModels.find((model) => model.id === modelSelect.value);
  if (!nextModel || nextModel.id === selectedModel.id) return;
  selectedModel = nextModel;
  resetConversation();
  updateSelectedModel();
});

// Verification and replies belong to the credential that initiated them.
// Clear them as soon as it changes, not only on the next Send.
apiKeyInput.addEventListener('input', resetConversation);

baseUrlInput.addEventListener('input', () => {
  const edited = baseUrlInput.value.trim() !== currentBaseUrl;
  if (edited && !endpointDirty) resetConversation();
  endpointDirty = edited;
  baseUrlInput.removeAttribute('aria-invalid');
});

baseUrlInput.addEventListener('change', () => {
  try {
    const baseUrl = normalizeBaseUrl(baseUrlInput.value);
    baseUrlInput.value = baseUrl;
    endpointDirty = false;
    baseUrlInput.removeAttribute('aria-invalid');
    errorElement.textContent = '';
    void switchEndpoint(baseUrl);
  } catch (error) {
    baseUrlInput.setAttribute('aria-invalid', 'true');
    errorElement.textContent = describeError(error);
  }
});

void loadModels(currentBaseUrl);

function describeError(error: unknown): string {
  if (isVerificationError(error) || isApiError(error)) {
    return `${error.message} (${error.failure.code})`;
  }
  return error instanceof Error ? error.message : 'Unexpected error';
}

function getClient(apiKey: string, baseUrl: string): InferenceClient {
  if (activeClient?.apiKey === apiKey && activeClient.baseUrl === baseUrl) return activeClient.client;
  const client = new InferenceClient({
    apiKey,
    baseUrl,
    signingAlgo: SIGNING_ALGO,
    e2ee: true,
    // NRAS has no browser CORS support. Vite relays only the evidence request;
    // this SDK verifier checks the signed NVIDIA verdict in the browser.
    modelVerification: {
      verifiers: {
        gpuEvidence: createGpuEvidenceVerifier({
          nrasUrl: new URL('/nvidia/nras', location.origin).href,
          jwksUrl: new URL('/nvidia/jwks', location.origin).href,
        }),
      },
    },
  });
  activeClient = { apiKey, baseUrl, client };
  return client;
}

async function checkGateway(apiKey: string, baseUrl: string): Promise<void> {
  setStatus('gateway', 'pending', 'Checking…', 'Fetching a fresh Gateway quote and checking its nonce, signer, TCB, and deployment binding.');
  const evidence = await new AttestationClient({ apiKey, baseUrl })
    .fetchGatewayAttestation({ signingAlgo: SIGNING_ALGO, includeSpkiFingerprint: false });
  const verified = await verifyGatewayAttestation(evidence);
  setStatus(
    'gateway',
    'verified',
    'Evidence verified',
    `Signer: ${verified.signer.signingAddress} · TCB: ${verified.tcbStatus} · OS image: ${verified.deployment.runtimeMeasurements.osImageHash ?? 'not reported'} · Compose: ${verified.deployment.runtimeMeasurements.composeHash ?? 'not reported'} · TLS peer pin: unavailable in browsers. This is a separate fresh check; the chat client also verifies Gateway evidence before sending.`,
  );
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const apiKey = apiKeyInput.value.trim();
  const prompt = promptInput.value.trim();
  if (!apiKey || !prompt || catalogLoading) {
    errorElement.textContent = catalogLoading
      ? 'Wait for the model list to load.'
      : 'Enter an API key and a message.';
    return;
  }
  let baseUrl: string;
  try {
    baseUrl = normalizeBaseUrl(baseUrlInput.value);
    baseUrlInput.value = baseUrl;
    baseUrlInput.removeAttribute('aria-invalid');
  } catch (error) {
    baseUrlInput.setAttribute('aria-invalid', 'true');
    errorElement.textContent = describeError(error);
    return;
  }

  isSending = true;
  sendButton.disabled = true;
  baseUrlInput.disabled = true;
  apiKeyInput.disabled = true;
  modelSelect.disabled = true;
  promptInput.disabled = true;
  let assistant: ReturnType<typeof addMessage> | undefined;
  try {
    if (baseUrl !== currentBaseUrl) await switchEndpoint(baseUrl);

    // A different credential or endpoint starts a separate conversation.
    if (activeClient && (activeClient.apiKey !== apiKey || activeClient.baseUrl !== baseUrl)) {
      resetConversation();
    }

    errorElement.textContent = '';
    promptInput.value = '';
    addMessage('user', prompt);
    assistant = addMessage('assistant', '');
    assistant.receipt.textContent = 'Waiting for evidence…';
    setStatus('model', 'pending', 'Checking…', 'The SDK will verify model evidence and an E2EE key before it sends this message.');

    await checkGateway(apiKey, baseUrl);
    const client = getClient(apiKey, baseUrl);
    const stream = await client.chat.completions.create({
      model: selectedModel.id,
      messages: [...history, { role: 'user', content: prompt }],
      stream: true,
    });
    setStatus('model', 'verified', 'Evidence verified · E2EE', 'The SDK accepted the model evidence and encrypted supported Chat fields to the attested model key.');

    let completionId: string | undefined;
    let answer = '';
    assistant.receipt.textContent = 'Streaming · response signature not checked yet';
    for await (const chunk of stream) {
      if (chunk.id) completionId = chunk.id;
      answer += chunk.choices[0]?.delta?.content ?? '';
      assistant.body.textContent = answer;
      messagesElement.scrollTop = messagesElement.scrollHeight;
    }
    if (!completionId) throw new Error('The stream ended without a completion ID; the response cannot be verified.');

    // Do not create a second client here: it would have no captured bytes for
    // this completion ID. Verification must follow full stream consumption.
    assistant.receipt.textContent = 'Checking exact response bytes and signature…';
    const verified = await client.verifyResponse(completionId);
    if (verified.signatureKind !== 'provider_tee') {
      assistant.receipt.textContent = `⚠ Gateway signature verified for ${completionId}; no model TEE signature. Do not treat this as a model-verified reply.`;
      errorElement.textContent = 'The response was not signed by the model TEE. It was not added to trusted chat history.';
      return;
    }
    assistant.receipt.textContent = `✓ Model response verified · ${completionId} · signer ${verified.attestation.signer.signingAddress} · TCB ${verified.attestation.tcbStatus}`;
    setStatus('model', 'verified', 'Evidence verified · E2EE', `Signer: ${verified.attestation.signer.signingAddress} · TCB: ${verified.attestation.tcbStatus} · GPU evidence: ${verified.attestation.gpuEvidence} · supported Chat fields encrypted to the attested model key.`);
    history.push({ role: 'user', content: prompt }, { role: 'assistant', content: answer });
  } catch (error) {
    const message = describeError(error);
    if (element<HTMLElement>('gateway-status').classList.contains('pending')) {
      setStatus('gateway', 'failed', 'Verification failed', message);
    }
    if (element<HTMLElement>('model-status').classList.contains('pending')) {
      setStatus('model', 'failed', 'Not verified', message);
    }
    if (assistant) assistant.receipt.textContent = `✕ Not verified: ${message}`;
    errorElement.textContent = message;
  } finally {
    isSending = false;
    sendButton.disabled = false;
    baseUrlInput.disabled = false;
    apiKeyInput.disabled = false;
    modelSelect.disabled = false;
    promptInput.disabled = false;
    promptInput.focus();
  }
});
