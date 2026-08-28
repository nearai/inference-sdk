import { createHash, X509Certificate } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';
import type { TLSSocket } from 'node:tls';
import { fetchGatewayAttestationWithRequester } from '../core/cloud-api';
import type {
  FetchedGatewayAttestation,
  FetchGatewayAttestationParams,
} from '../types/cloud-api';

type GatewayAttestationResponse = {
  readonly response: Response;
  readonly peerSpkiFingerprint?: string;
};

/**
 * Fetch Gateway evidence through Node HTTPS so the TLS peer for the exact
 * request can be included in the client binding.
 */
export function fetchGatewayAttestation(
  params: FetchGatewayAttestationParams,
): Promise<FetchedGatewayAttestation> {
  return fetchGatewayAttestationWithRequester(
    params,
    requestGatewayAttestation,
  );
}

function requestGatewayAttestation(
  request: Request,
): Promise<GatewayAttestationResponse> {
  return new Promise((resolve, reject) => {
    const nativeRequest = httpsRequest(
      request.url,
      {
        agent: false,
        method: request.method,
        headers: Object.fromEntries(request.headers),
      },
      (incoming) => {
        try {
          const certificate = peerCertificate(incoming.socket as TLSSocket);
          const peerSpkiFingerprint =
            certificate === undefined
              ? undefined
              : createHash('sha256')
                  .update(
                    certificate.publicKey.export({
                      type: 'spki',
                      format: 'der',
                    }),
                  )
                  .digest('hex');
          const body = Readable.toWeb(incoming) as ReadableStream<Uint8Array>;
          resolve({
            response: new Response(body, {
              status: incoming.statusCode ?? 500,
              statusText: incoming.statusMessage,
            }),
            ...(peerSpkiFingerprint === undefined
              ? {}
              : { peerSpkiFingerprint }),
          });
        } catch (cause) {
          reject(cause);
        }
      },
    );
    nativeRequest.once('error', reject);
    nativeRequest.end();
  });
}

function peerCertificate(socket: TLSSocket): X509Certificate | undefined {
  const certificate = socket.getPeerX509Certificate();
  if (certificate !== undefined) {
    return certificate;
  }

  const peer = socket.getPeerCertificate(true);
  return peer.raw === undefined ? undefined : new X509Certificate(peer.raw);
}
