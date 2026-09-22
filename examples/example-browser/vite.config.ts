import { defineConfig, type ProxyOptions } from 'vite';

const stripBrowserHeaders: ProxyOptions['configure'] = (proxy) => {
  // This example's TS config includes browser types only; keep the Node proxy
  // event surface local instead of pulling Node types into browser source.
  const eventProxy = proxy as unknown as {
    on(event: 'proxyReq', listener: (request: { removeHeader(name: string): void }) => void): void;
  };
  eventProxy.on('proxyReq', (proxyRequest) => {
    // NRAS rejects the browser's localhost Origin as an invalid CORS request.
    // These headers are unnecessary for the evidence relay and must not leak
    // local cookies or credentials to the upstream service either.
    for (const header of ['origin', 'referer', 'cookie', 'authorization']) {
      proxyRequest.removeHeader(header);
    }
  });
};

// Development-only transport for NVIDIA NRAS, whose endpoint does not allow
// browser CORS preflights. The SDK still checks NVIDIA's signed JWT in-browser.
// Do not expose this unauthenticated Vite proxy as a production relay.
export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/nvidia/nras': {
        target: 'https://nras.attestation.nvidia.com',
        changeOrigin: true,
        rewrite: () => '/v3/attest/gpu',
        configure: stripBrowserHeaders,
      },
      '/nvidia/jwks': {
        target: 'https://nras.attestation.nvidia.com',
        changeOrigin: true,
        rewrite: () => '/.well-known/jwks.json',
        configure: stripBrowserHeaders,
      },
    },
  },
});
