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

// Development-only relays for Intel collateral and NVIDIA evidence services.
// Cryptographic verification still runs in the browser.
// Do not expose this unauthenticated Vite proxy as a production relay.
export default defineConfig({
  plugins: [{
    name: 'intel-root-ca-crl',
    configureServer(server) {
      // PCCS serves a hex-encoded root CRL here. Intel PCS has no equivalent
      // endpoint, so relay the DER file from Intel's certificate service.
      server.middlewares.use('/intel/sgx/certification/v4/rootcacrl', async (_request, response, next) => {
        try {
          const upstream = await fetch('https://certificates.trustedservices.intel.com/IntelSGXRootCA.der');
          response.statusCode = upstream.status;
          if (!upstream.ok) { response.end(); return; }
          const bytes = new Uint8Array(await upstream.arrayBuffer());
          const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
          response.setHeader('Content-Type', 'text/plain');
          response.end(hex);
        } catch (error) {
          next(error);
        }
      });
    },
  }],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/intel': {
        target: 'https://api.trustedservices.intel.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/intel/, ''),
        configure: stripBrowserHeaders,
      },
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
