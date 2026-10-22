const isNode =
  typeof window === 'undefined' &&
  typeof process !== 'undefined' &&
  Boolean(process.versions?.node);

export const INTEL_PCCS_API_URL = isNode
  ? 'https://api.trustedservices.intel.com'
  : 'https://cloud.near.ai/api/proxy/pccs';

export const NVIDIA_GPU_VERIFIER_API_URL = isNode
  ? 'https://nras.attestation.nvidia.com/v3/attest/gpu'
  : 'https://cloud.near.ai/api/proxy/nras/v3/attest/gpu';
