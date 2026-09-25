import {
  AttestationClient,
  InferenceClient,
  createGpuEvidenceVerifier,
  isApiError,
  isVerificationError,
  verifyGatewayAttestation,
  verifyModelAttestation,
  type GatewayAttestation,
  type ModelAttestation,
  type VerifiedCompletionResult,
  type VerifiedGatewayAttestation,
  type VerifiedModelAttestation,
} from '@nearai/inference-sdk';
import './style.css';

const DEFAULT_BASE_URL = 'https://cloud-api.near.ai/v1';
const SIGNING_ALGO = 'ed25519';
const DEFAULT_MODEL = { id: 'z-ai/glm-5.3-flash', label: 'GLM 5.3 Flash' };

type ChatMessage = { role: 'user' | 'assistant'; content: string };
type Status = 'idle' | 'pending' | 'verified' | 'failed';
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
type VerificationRecord = {
  ordinal: number;
  modelName: string;
  prompt: string;
  content: string;
  status: Status;
  error?: string;
  completionId?: string;
  client?: InferenceClient;
  result?: VerifiedCompletionResult;
  verifiedAt?: number;
  retryableLookup?: boolean;
  receipt: HTMLElement;
};
type HardwareReport = {
  gateway: { raw: GatewayAttestation; verified: VerifiedGatewayAttestation };
  model: { raw: ModelAttestation; verified: VerifiedModelAttestation };
};

const baseUrlInput = element<HTMLInputElement>('base-url');
const apiKeyInput = element<HTMLInputElement>('api-key');
const modelSelect = element<HTMLSelectElement>('model-select');
const promptInput = element<HTMLInputElement>('prompt');
const form = element<HTMLFormElement>('chat-form');
const sendButton = element<HTMLButtonElement>('send');
const messagesElement = element<HTMLDivElement>('messages');
const errorElement = element<HTMLParagraphElement>('error');
const verificationDialog = element<HTMLDialogElement>('verification-dialog');
const hardwareDialog = element<HTMLDialogElement>('hardware-dialog');
const responseDialog = element<HTMLDialogElement>('response-dialog');
const history: ChatMessage[] = [];
const verificationRecords: VerificationRecord[] = [];
const emptyState = element<HTMLElement>('empty-state').cloneNode(true);
let selectedModel: SelectableModel = DEFAULT_MODEL;
let availableModels: SelectableModel[] = [DEFAULT_MODEL];
let currentBaseUrl = DEFAULT_BASE_URL;
let catalogRequestId = 0;
let catalogLoading = false;
let isSending = false;
let endpointDirty = false;
let gatewayStatus: Status = 'idle';
let modelStatus: Status = 'idle';
let gatewayError: string | undefined;
let modelError: string | undefined;
let hardwareReport: HardwareReport | undefined;
let hardwareTab: 'model' | 'gateway' = 'model';
let hardwareRequestId = 0;

// verifyResponse(id) must run on the client that captured the exact encrypted
// request and response bytes, so keep that client alive for each receipt.
let activeClient: { apiKey: string; baseUrl: string; client: InferenceClient } | undefined;

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing element: ${id}`);
  return value as T;
}

function node<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== undefined) value.textContent = text;
  return value;
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

function describeError(error: unknown): string {
  if (isVerificationError(error) || isApiError(error)) {
    return `${error.message} (${error.failure.code})`;
  }
  return error instanceof Error ? error.message : 'Unexpected error';
}

function gpuVerifier() {
  return createGpuEvidenceVerifier({
    // Vite relays evidence only. The SDK still verifies NVIDIA's signed
    // verdict, issuer, and nonce in the browser.
    nrasUrl: new URL('/nvidia/nras', location.origin).href,
    jwksUrl: new URL('/nvidia/jwks', location.origin).href,
  });
}

function updateSelectedModel(): void {
  element<HTMLElement>('model-id').textContent = selectedModel.id;
  element<HTMLElement>('model-avatar').textContent = selectedModel.id[0]?.toUpperCase() ?? 'M';
  element<HTMLElement>('hardware-model-avatar').textContent = selectedModel.id[0]?.toUpperCase() ?? 'M';
  element<HTMLElement>('hardware-model-name').textContent = selectedModel.label;
  promptInput.placeholder = `Message ${selectedModel.label}…`;
}

function selectableModel(value: unknown): SelectableModel | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const model = value as CatalogModel;
  const metadata = model.metadata;
  if (
    typeof model.modelId !== 'string' || !metadata ||
    metadata.verifiable !== true || metadata.attestationSupported !== true ||
    typeof metadata.providerType !== 'string' || metadata.providerType.trim().toLowerCase() !== 'vllm' ||
    metadata.isReady !== true ||
    !Array.isArray(metadata.architecture?.inputModalities) || !metadata.architecture.inputModalities.includes('text') ||
    !Array.isArray(metadata.architecture.outputModalities) || !metadata.architecture.outputModalities.includes('text')
  ) return undefined;
  return {
    id: model.modelId,
    label: typeof metadata.modelDisplayName === 'string' && metadata.modelDisplayName.trim()
      ? metadata.modelDisplayName : model.modelId,
  };
}

async function loadModels(baseUrl: string): Promise<void> {
  const requestId = ++catalogRequestId;
  catalogLoading = true;
  sendButton.disabled = true;
  modelSelect.disabled = true;
  try {
    const response = await fetch(`${baseUrl}/model/list?limit=500&offset=0`, { signal: AbortSignal.timeout(5000) });
    if (requestId !== catalogRequestId) return;
    if (!response.ok) throw new Error(`Model catalog returned HTTP ${response.status}`);
    const catalog: unknown = await response.json();
    if (requestId !== catalogRequestId) return;
    const entries = catalog && typeof catalog === 'object' && 'models' in catalog ? catalog.models : undefined;
    if (!Array.isArray(entries)) throw new Error('Model catalog response is invalid');
    const models = entries.map(selectableModel).filter((model): model is SelectableModel => model !== undefined)
      .sort((a, b) => a.label.localeCompare(b.label));
    if (models.length === 0) throw new Error('No compatible Private TEE chat models are available');
    availableModels = models;
    modelSelect.replaceChildren(...models.map((model) => new Option(model.label, model.id)));
    const nextModel = models.find((model) => model.id === selectedModel.id) ?? models[0]!;
    if (nextModel.id !== selectedModel.id) resetConversation();
    selectedModel = nextModel;
    modelSelect.value = selectedModel.id;
    modelSelect.title = '';
    updateSelectedModel();
  } catch (error) {
    if (requestId !== catalogRequestId) return;
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

function combinedStatus(): Status {
  if (gatewayStatus === 'failed' || modelStatus === 'failed' || verificationRecords.some((record) => record.status === 'failed')) return 'failed';
  if (gatewayStatus === 'pending' || modelStatus === 'pending' || verificationRecords.some((record) => record.status === 'pending')) return 'pending';
  if (gatewayStatus === 'verified' && modelStatus === 'verified' && verificationRecords.length > 0 && verificationRecords.every((record) => record.status === 'verified')) return 'verified';
  return 'idle';
}

function updateVerificationSummary(): void {
  const status = combinedStatus();
  const labels: Record<Status, string> = {
    idle: 'Not checked', pending: 'Verifying confidentiality', verified: 'Chat is confidential', failed: 'Verification needs attention',
  };
  const copy: Record<Status, string> = {
    idle: 'Send a prompt to verify model evidence, Gateway evidence, E2EE and the completion signature.',
    pending: 'Verification is running. A response is not trusted until its completion signature has been checked.',
    verified: 'Model evidence, Gateway evidence and every completion signature in this conversation were verified.',
    failed: gatewayError || modelError || 'At least one verification check failed. Treat the affected response as unverified.',
  };
  const glyph: Record<Status, string> = { idle: '◇', pending: '◌', verified: '✓', failed: '!' };
  const statusLabel = element<HTMLElement>('verification-status');
  statusLabel.className = `status ${status}`;
  statusLabel.textContent = labels[status];
  const sidebarIcon = element<HTMLElement>('verification-icon');
  sidebarIcon.className = `verification-shield ${status}`;
  sidebarIcon.textContent = glyph[status];
  element<HTMLElement>('assurance-card').className = `assurance-card ${status}`;
  element<HTMLElement>('assurance-icon').textContent = glyph[status];
  element<HTMLElement>('assurance-title').textContent = labels[status];
  element<HTMLElement>('assurance-copy').textContent = copy[status];
  element<HTMLButtonElement>('open-hardware').disabled = !apiKeyInput.value.trim();
  renderVerificationRecords();
}

function setStageStatus(stage: 'gateway' | 'model', status: Status, error?: string): void {
  if (stage === 'gateway') { gatewayStatus = status; gatewayError = error; }
  else { modelStatus = status; modelError = error; }
  updateVerificationSummary();
}

function renderReceipt(record: VerificationRecord): void {
  record.receipt.replaceChildren();
  record.receipt.className = `note ${record.status}`;
  if (record.status === 'verified') {
    const button = node('button', 'receipt-button verified', '✓ Verified');
    button.type = 'button';
    button.addEventListener('click', () => openResponseDetails(record));
    record.receipt.append(button);
    return;
  }
  record.receipt.textContent = record.status === 'pending'
    ? '◌ Verifying response signature…'
    : `✕ Not verified${record.error ? `: ${record.error}` : ''}`;
}

function detailCell(label: string, value: string): HTMLElement {
  const cell = node('div', 'detail-cell');
  cell.append(node('span', undefined, label), node('strong', undefined, value));
  return cell;
}

function renderVerificationRecords(): void {
  const container = element<HTMLElement>('verification-records');
  const verifiedCount = verificationRecords.filter((record) => record.status === 'verified').length;
  element<HTMLElement>('verified-count').textContent = String(verifiedCount);
  element<HTMLElement>('message-total').textContent = `${verificationRecords.length} total`;
  if (verificationRecords.length === 0) {
    container.replaceChildren(node('div', 'empty-verification', 'Send a prompt to see per-message verification results.'));
    return;
  }
  container.replaceChildren(...verificationRecords.map((record) => {
    const card = node('details', 'record');
    const summary = node('summary');
    const heading = node('span', 'record-heading');
    const row = node('span', 'record-heading-row');
    row.append(node('strong', undefined, `Message ${record.ordinal}`));
    row.append(node('span', `result-badge ${record.status}`, record.status === 'verified' ? 'Verified' : record.status === 'pending' ? 'Verifying' : 'Failed'));
    heading.append(row, node('span', 'record-preview', `${record.modelName} · ${record.content || 'No response content'}`));
    summary.append(node('span', 'record-chevron', '›'), heading);
    const detail = node('div', 'record-detail');
    if (record.status === 'verified' && record.result) {
      detail.append(node('div', 'verified-line', `✓ Verified ${record.result.signature.signer.signingAlgo.toUpperCase()} signature`));
      const grid = node('div', 'compact-grid');
      grid.append(detailCell('Completion ID', record.result.completionId), detailCell('Signature scope', record.result.signatureKind === 'provider_tee' ? 'Model TEE' : 'Cloud gateway'));
      detail.append(grid);
      const open = node('button', 'secondary-button', 'View response verification');
      open.type = 'button';
      open.addEventListener('click', () => openResponseDetails(record));
      detail.append(open);
    } else {
      detail.append(node('div', record.status === 'failed' ? 'failure-copy' : undefined, record.error || 'Verification is still running.'));
      if (record.status === 'failed' && record.retryableLookup && record.client && record.completionId) {
        const retry = node('button', 'secondary-button', '↻ Re-verify message');
        retry.type = 'button';
        retry.addEventListener('click', () => void retryVerification(record));
        detail.append(retry);
      }
    }
    card.append(summary, detail);
    return card;
  }));
}

function addMessage(role: 'user' | 'assistant', content: string): { body: HTMLParagraphElement; receipt: HTMLDivElement } {
  document.getElementById('empty-state')?.remove();
  const card = node('article', `message ${role}`);
  const body = node('p', undefined, content);
  const receipt = node('div', 'note');
  card.append(node('strong', undefined, role === 'user' ? 'You' : selectedModel.label), body, receipt);
  messagesElement.append(card);
  messagesElement.scrollTop = messagesElement.scrollHeight;
  return { body, receipt };
}

function resetConversation(): void {
  activeClient = undefined;
  hardwareRequestId += 1;
  history.length = 0;
  verificationRecords.length = 0;
  hardwareReport = undefined;
  gatewayStatus = 'idle'; modelStatus = 'idle';
  gatewayError = undefined; modelError = undefined;
  messagesElement.replaceChildren(emptyState.cloneNode(true));
  errorElement.textContent = '';
  updateVerificationSummary();
}

function rebuildTrustedHistory(): void {
  history.length = 0;
  for (const record of verificationRecords) {
    if (record.status !== 'verified') continue;
    history.push(
      { role: 'user', content: record.prompt },
      { role: 'assistant', content: record.content },
    );
  }
}

function getClient(apiKey: string, baseUrl: string): InferenceClient {
  if (activeClient?.apiKey === apiKey && activeClient.baseUrl === baseUrl) return activeClient.client;
  const client = new InferenceClient({
    apiKey, baseUrl, signingAlgo: SIGNING_ALGO, e2ee: true,
    modelVerification: { verifiers: { gpuEvidence: gpuVerifier() } },
  });
  activeClient = { apiKey, baseUrl, client };
  return client;
}

async function checkGateway(apiKey: string, baseUrl: string): Promise<void> {
  setStageStatus('gateway', 'pending');
  try {
    const evidence = await new AttestationClient({ apiKey, baseUrl }).fetchGatewayAttestation({ signingAlgo: SIGNING_ALGO, includeSpkiFingerprint: false });
    await verifyGatewayAttestation(evidence);
    setStageStatus('gateway', 'verified');
  } catch (error) {
    setStageStatus('gateway', 'failed', describeError(error));
    throw error;
  }
}

function requireModelSignature(result: VerifiedCompletionResult): void {
  if (result.signatureKind !== 'provider_tee') throw new Error('The completion was signed by the Gateway, not the verified model TEE.');
}

function isRetryableSignatureLookup(error: unknown): boolean {
  return isApiError(error) && error.retryable;
}

async function retryVerification(record: VerificationRecord): Promise<void> {
  if (!record.client || !record.completionId) return;
  record.status = 'pending'; record.error = undefined;
  renderReceipt(record); updateVerificationSummary();
  try {
    const result = await record.client.verifyResponse(record.completionId);
    requireModelSignature(result);
    record.result = result; record.verifiedAt = Date.now(); record.status = 'verified'; record.retryableLookup = false;
    rebuildTrustedHistory();
  } catch (error) {
    record.status = 'failed'; record.error = describeError(error); record.retryableLookup = isRetryableSignatureLookup(error);
  }
  renderReceipt(record); updateVerificationSummary();
}

function showDialog(dialog: HTMLDialogElement): void { if (!dialog.open) dialog.showModal(); }
function closeDialog(dialog: HTMLDialogElement): void { if (dialog.open) dialog.close(); }

function copyBlock(label: string, value?: string): HTMLElement | undefined {
  if (!value) return undefined;
  const block = node('div', 'copy-block');
  const heading = node('div', 'copy-heading');
  heading.append(node('span', undefined, label));
  const copy = node('button', 'copy-button', 'Copy');
  copy.type = 'button';
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      copy.textContent = 'Copied';
      window.setTimeout(() => { copy.textContent = 'Copy'; }, 1200);
    } catch { copy.textContent = 'Unavailable'; }
  });
  heading.append(copy);
  block.append(heading, node('pre', 'copy-value', value));
  return block;
}

function detailRow(label: string, value?: string): HTMLElement | undefined {
  if (!value) return undefined;
  const row = node('div', 'detail-row');
  row.append(node('dt', undefined, label), node('dd', undefined, value));
  return row;
}

function appendDefined(parent: HTMLElement, ...children: Array<HTMLElement | undefined>): void {
  for (const child of children) if (child) parent.append(child);
}

function evidenceSection(title: string, description: string, ...children: Array<HTMLElement | undefined>): HTMLElement {
  const section = node('details', 'evidence-section');
  section.append(node('summary', undefined, title));
  const body = node('div', 'evidence-section-body');
  body.append(node('p', undefined, description));
  appendDefined(body, ...children);
  section.append(body);
  return section;
}

function renderHardwarePanel(): void {
  if (!hardwareReport) return;
  const panel = element<HTMLElement>('hardware-panel');
  const entry = hardwareTab === 'model' ? hardwareReport.model : hardwareReport.gateway;
  const { raw, verified } = entry;
  const summary = node('div', 'summary-grid');
  summary.append(
    detailCell('Status', 'Verified'), detailCell('TCB status', verified.tcbStatus),
    detailCell('Signing algorithm', verified.signer.signingAlgo.toUpperCase()),
    detailCell('Deployment policy', verified.deploymentProvenance === 'verified' ? 'Verified' : 'Measurements verified'),
  );
  const eventLog = typeof raw.eventLog === 'string' ? raw.eventLog : JSON.stringify(raw.eventLog, null, 2);
  const tdx = evidenceSection(
    'TDX Attestation · Intel',
    'Intel TDX provides a hardware-isolated environment and issues cryptographically signed attestation reports.',
    copyBlock('Quote', raw.intelQuote), copyBlock('Request nonce', raw.nonce),
    copyBlock('Report data', raw.reportedQuoteData), copyBlock('Event log', eventLog),
    copyBlock('OS image hash', verified.deployment.runtimeMeasurements.osImageHash),
    copyBlock('Compose hash', verified.deployment.runtimeMeasurements.composeHash),
    copyBlock('App compose', verified.deployment.appCompose),
    copyBlock('Advisories', verified.advisoryIds.length ? verified.advisoryIds.join(', ') : 'None'),
  );
  const children: HTMLElement[] = [summary, copyBlock('Signing address', verified.signer.signingAddress)!];
  if (hardwareTab === 'model') {
    const modelRaw = raw as ModelAttestation;
    const modelVerified = verified as VerifiedModelAttestation;
    children.push(evidenceSection(
      'GPU Attestation · NVIDIA',
      modelVerified.gpuEvidence === 'verified'
        ? 'NVIDIA Remote Attestation Service verified the GPU evidence and the SDK checked its signed verdict.'
        : 'This attestation did not provide GPU evidence.',
      copyBlock('Raw NVIDIA payload', modelRaw.nvidiaPayload),
      copyBlock('Model signing public key', modelVerified.signingPublicKey),
    ));
  }
  children.push(tdx);
  panel.replaceChildren(...children);
}

function showHardwareError(message: string): void {
  const error = element<HTMLElement>('hardware-error');
  error.textContent = message; error.hidden = false;
  element<HTMLElement>('hardware-content').hidden = true;
}

async function verifyHardware(): Promise<void> {
  const requestId = ++hardwareRequestId;
  let baseUrl: string;
  try { baseUrl = normalizeBaseUrl(baseUrlInput.value); }
  catch (error) { showHardwareError(describeError(error)); return; }
  const apiKey = apiKeyInput.value.trim();
  if (!apiKey) { showHardwareError('Enter an API key to fetch fresh attestation evidence.'); return; }
  const loading = element<HTMLElement>('hardware-loading');
  const error = element<HTMLElement>('hardware-error');
  const content = element<HTMLElement>('hardware-content');
  const badge = element<HTMLElement>('hardware-badge');
  loading.hidden = false; error.hidden = true; content.hidden = true;
  badge.className = 'result-badge pending'; badge.textContent = 'Verifying';
  element<HTMLButtonElement>('verify-again').disabled = true;
  try {
    const client = new AttestationClient({ apiKey, baseUrl });
    const [gatewayFetched, modelFetched] = await Promise.all([
      client.fetchGatewayAttestation({ signingAlgo: SIGNING_ALGO, includeSpkiFingerprint: false }),
      client.fetchModelAttestations({ model: selectedModel.id, signingAlgo: SIGNING_ALGO }),
    ]);
    const [gatewayVerified, modelVerified] = await Promise.all([
      verifyGatewayAttestation(gatewayFetched),
      Promise.all(modelFetched.attestations.map((attestation) => verifyModelAttestation({
        attestation, clientBinding: modelFetched.clientBinding,
        verifiers: { gpuEvidence: gpuVerifier() },
      }))),
    ]);
    if (requestId !== hardwareRequestId) return;
    const modelIndex = modelVerified.findIndex((result) => result.signingPublicKey !== undefined);
    if (modelIndex < 0) throw new Error('No verified model attestation supplied an E2EE public key.');
    hardwareReport = {
      gateway: { raw: gatewayFetched.attestation, verified: gatewayVerified },
      model: { raw: modelFetched.attestations[modelIndex]!, verified: modelVerified[modelIndex]! },
    };
    badge.className = 'result-badge verified'; badge.textContent = 'Verified';
    loading.hidden = true; content.hidden = false;
    renderHardwarePanel();
  } catch (cause) {
    if (requestId !== hardwareRequestId) return;
    hardwareReport = undefined;
    badge.className = 'result-badge failed'; badge.textContent = 'Failed';
    loading.hidden = true; showHardwareError(describeError(cause));
  } finally {
    if (requestId === hardwareRequestId) element<HTMLButtonElement>('verify-again').disabled = false;
  }
}

function openResponseDetails(record: VerificationRecord): void {
  if (!record.result || !record.verifiedAt) return;
  const result = record.result;
  const content = element<HTMLElement>('response-content');
  const success = node('section', 'success-panel');
  success.append(node('strong', undefined, '✓ Response signature verified'), node('p', undefined, 'A verified model TEE signer signed this completion.'));
  const encryption = node('section', 'info-panel');
  encryption.append(node('strong', undefined, '▣ End-to-end encrypted'), node('p', undefined, 'The prompt was encrypted for the verified model TEE before inference.'));
  const signature = node('section', 'attestation-panel');
  signature.append(node('strong', undefined, 'Response signature'));
  const list = node('dl', 'detail-list');
  appendDefined(
    list, detailRow('Completion ID', result.completionId),
    detailRow('Signature scope', result.signatureKind === 'provider_tee' ? 'Model TEE' : 'Cloud gateway'),
    detailRow('Signing algorithm', result.signature.signer.signingAlgo.toUpperCase()),
    detailRow('Completion signer', result.signature.signer.signingAddress),
    detailRow('Verified at', new Date(record.verifiedAt).toLocaleString()),
  );
  const signerMatches = result.signature.signer.signingAlgo === result.attestation.signer.signingAlgo &&
    result.signature.signer.signingAddress.toLowerCase() === result.attestation.signer.signingAddress.toLowerCase();
  signature.append(list, node('div', 'matched-line', signerMatches
    ? '✓ The signer matches the verified attestation identity.'
    : '✕ The signer does not match the verified attestation identity.'));
  const attestations = node('section', 'attestation-panel');
  attestations.append(node('strong', undefined, 'Attestation checks passed'), node('p', undefined, 'The model TEE and NEAR AI Cloud Gateway attestations were verified.'));
  const hardware = node('button', 'secondary-button', 'View hardware verification');
  hardware.type = 'button';
  hardware.addEventListener('click', () => { closeDialog(responseDialog); openHardwareDialog(); });
  attestations.append(hardware);
  content.replaceChildren(success, encryption, signature, attestations);
  appendDefined(content, copyBlock('Signed message', result.signature.signedText), copyBlock('Signature', result.signature.signature));
  showDialog(responseDialog);
}

function openHardwareDialog(): void {
  updateSelectedModel();
  showDialog(hardwareDialog);
  void verifyHardware();
}

modelSelect.addEventListener('change', () => {
  const nextModel = availableModels.find((model) => model.id === modelSelect.value);
  if (!nextModel || nextModel.id === selectedModel.id) return;
  selectedModel = nextModel; resetConversation(); updateSelectedModel();
});
apiKeyInput.addEventListener('input', resetConversation);
baseUrlInput.addEventListener('input', () => {
  const edited = baseUrlInput.value.trim() !== currentBaseUrl;
  if (edited && !endpointDirty) resetConversation();
  endpointDirty = edited; baseUrlInput.removeAttribute('aria-invalid');
});
baseUrlInput.addEventListener('change', () => {
  try {
    const baseUrl = normalizeBaseUrl(baseUrlInput.value);
    baseUrlInput.value = baseUrl; endpointDirty = false;
    baseUrlInput.removeAttribute('aria-invalid'); errorElement.textContent = '';
    void switchEndpoint(baseUrl);
  } catch (error) {
    baseUrlInput.setAttribute('aria-invalid', 'true'); errorElement.textContent = describeError(error);
  }
});

element<HTMLButtonElement>('open-verification').addEventListener('click', () => showDialog(verificationDialog));
element<HTMLButtonElement>('open-hardware').addEventListener('click', openHardwareDialog);
element<HTMLButtonElement>('verify-again').addEventListener('click', () => void verifyHardware());
element<HTMLButtonElement>('model-tab').addEventListener('click', () => {
  hardwareTab = 'model';
  element<HTMLButtonElement>('model-tab').classList.add('active');
  element<HTMLButtonElement>('model-tab').setAttribute('aria-selected', 'true');
  element<HTMLButtonElement>('gateway-tab').classList.remove('active');
  element<HTMLButtonElement>('gateway-tab').setAttribute('aria-selected', 'false');
  renderHardwarePanel();
});
element<HTMLButtonElement>('gateway-tab').addEventListener('click', () => {
  hardwareTab = 'gateway';
  element<HTMLButtonElement>('gateway-tab').classList.add('active');
  element<HTMLButtonElement>('gateway-tab').setAttribute('aria-selected', 'true');
  element<HTMLButtonElement>('model-tab').classList.remove('active');
  element<HTMLButtonElement>('model-tab').setAttribute('aria-selected', 'false');
  renderHardwarePanel();
});
document.querySelectorAll<HTMLElement>('[data-close]').forEach((button) => {
  button.addEventListener('click', () => closeDialog(element<HTMLDialogElement>(button.dataset.close!)));
});
for (const dialog of [verificationDialog, hardwareDialog, responseDialog]) {
  dialog.addEventListener('click', (event) => { if (event.target === dialog) closeDialog(dialog); });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const apiKey = apiKeyInput.value.trim();
  const prompt = promptInput.value.trim();
  if (!apiKey || !prompt || catalogLoading) {
    errorElement.textContent = catalogLoading ? 'Wait for the model list to load.' : 'Enter an API key and a message.';
    return;
  }
  let baseUrl: string;
  try {
    baseUrl = normalizeBaseUrl(baseUrlInput.value);
    baseUrlInput.value = baseUrl; baseUrlInput.removeAttribute('aria-invalid');
  } catch (error) {
    baseUrlInput.setAttribute('aria-invalid', 'true'); errorElement.textContent = describeError(error); return;
  }
  isSending = true;
  sendButton.disabled = true; baseUrlInput.disabled = true; apiKeyInput.disabled = true;
  modelSelect.disabled = true; promptInput.disabled = true;
  let record: VerificationRecord | undefined;
  try {
    if (baseUrl !== currentBaseUrl) await switchEndpoint(baseUrl);
    if (activeClient && (activeClient.apiKey !== apiKey || activeClient.baseUrl !== baseUrl)) resetConversation();
    errorElement.textContent = ''; promptInput.value = '';
    addMessage('user', prompt);
    const assistant = addMessage('assistant', '');
    record = { ordinal: verificationRecords.length + 1, modelName: selectedModel.label, prompt, content: '', status: 'pending', receipt: assistant.receipt };
    verificationRecords.push(record); renderReceipt(record); setStageStatus('model', 'pending');
    await checkGateway(apiKey, baseUrl);
    const client = getClient(apiKey, baseUrl);
    record.client = client;
    const stream = await client.chat.completions.create({
      model: selectedModel.id, messages: [...history, { role: 'user', content: prompt }], stream: true,
    });
    setStageStatus('model', 'verified');
    let completionId: string | undefined;
    let answer = '';
    for await (const chunk of stream) {
      if (chunk.id) completionId = chunk.id;
      answer += chunk.choices[0]?.delta?.content ?? '';
      assistant.body.textContent = answer; record.content = answer;
      messagesElement.scrollTop = messagesElement.scrollHeight;
    }
    if (!completionId) throw new Error('The stream ended without a completion ID; the response cannot be verified.');
    record.completionId = completionId;
    const result = await client.verifyResponse(completionId);
    requireModelSignature(result);
    record.result = result; record.verifiedAt = Date.now(); record.status = 'verified'; record.retryableLookup = false;
    renderReceipt(record); updateVerificationSummary();
    rebuildTrustedHistory();
  } catch (error) {
    const message = describeError(error);
    if (modelStatus === 'pending') setStageStatus('model', 'failed', message);
    if (record) {
      record.status = 'failed'; record.error = message;
      record.retryableLookup = isRetryableSignatureLookup(error);
      renderReceipt(record);
    }
    updateVerificationSummary(); errorElement.textContent = message;
  } finally {
    isSending = false;
    sendButton.disabled = false; baseUrlInput.disabled = false; apiKeyInput.disabled = false;
    modelSelect.disabled = false; promptInput.disabled = false; promptInput.focus();
  }
});

updateVerificationSummary();
void loadModels(currentBaseUrl);
