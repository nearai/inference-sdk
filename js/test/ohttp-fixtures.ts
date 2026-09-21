import { Buffer } from 'node:buffer';
import {
  AEAD_AES_128_GCM,
  CipherSuite,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from 'hpke';
import { ChunkedOHTTPServer, KeyConfig } from 'ohttp-ts';
import nacl from 'tweetnacl';

type CreateOhttpEndpointParams = {
  readonly fetch: typeof globalThis.fetch;
  readonly signingKey: nacl.SignKeyPair;
  readonly truncateResponse?: boolean;
};

/** Add real signed OHTTP to an existing in-memory attestation/Chat endpoint. */
export async function createOhttpEndpoint({
  fetch: innerFetch,
  signingKey,
  truncateResponse = false,
}: CreateOhttpEndpointParams) {
  const config = await KeyConfig.generate(
    new CipherSuite(
      KEM_DHKEM_X25519_HKDF_SHA256,
      KDF_HKDF_SHA256,
      AEAD_AES_128_GCM,
    ),
    1,
  );
  const keyConfig = KeyConfig.serialize(config);
  // Put SSE content in a non-final frame when testing trailing authentication.
  const server = new ChunkedOHTTPServer([config], {
    padding: truncateResponse ? 32768 : 16384,
  });
  let responseController: ReadableStreamDefaultController<Uint8Array>;
  const attestation = {
    signing_algo: 'ed25519',
    signing_key: Buffer.from(signingKey.publicKey).toString('hex'),
    key_config: Buffer.from(keyConfig).toString('hex'),
    signature: Buffer.from(
      nacl.sign.detached(keyConfig, signingKey.secretKey),
    ).toString('hex'),
  };
  const requests: Request[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    requests.push(request.clone());
    const url = new URL(request.url);
    if (url.pathname === '/ohttp') {
      const decoded = await server.decapsulateRequest(request);
      const response = await decoded.context.encapsulateResponse(
        await innerFetch(decoded.request),
      );
      if (!truncateResponse) return response;
      const bytes = new Uint8Array(await response.arrayBuffer());
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            responseController = controller;
            controller.enqueue(bytes.slice(0, -1));
          },
        }),
        response,
      );
    }
    const response = await innerFetch(request);
    if (url.pathname !== '/v1/attestation/report') return response;
    return Response.json({
      ...(await response.json()),
      ohttp_attestation: attestation,
    });
  };
  return { fetch, requests, finishResponse: () => responseController.close() };
}
