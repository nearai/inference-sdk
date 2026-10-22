test('uses attestation proxies in a browser window with Node.js integration', () => {
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: globalThis,
  });
  try {
    jest.isolateModules(() => {
      const {
        INTEL_PCCS_API_URL,
        NVIDIA_GPU_VERIFIER_API_URL,
      } = require('../src/utils/consts');
      expect(INTEL_PCCS_API_URL).toBe('https://cloud.near.ai/api/proxy/pccs');
      expect(NVIDIA_GPU_VERIFIER_API_URL).toBe(
        'https://cloud.near.ai/api/proxy/nras/v3/attest/gpu',
      );
    });
  } finally {
    Reflect.deleteProperty(globalThis, 'window');
  }
});
