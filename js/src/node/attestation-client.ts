import { createHash, X509Certificate } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';
import type { TLSSocket } from 'node:tls';
import {
  CloudApiClient,
  type GatewayAttestationHttpResponse,
} from '../core/cloud-api';
import type {
  FetchedGatewayAttestation,
  NodeFetchGatewayAttestationParams,
} from '../types/cloud-api';

/**
 * Node client that captures the TLS peer for Gateway attestation requests.
 */
export class AttestationClient extends CloudApiClient {
  async fetchGatewayAttestation({
    signingAlgo,
    includeSpkiFingerprint = true,
  }: NodeFetchGatewayAttestationParams = {}): Promise<FetchedGatewayAttestation> {
    return this.fetchGatewayAttestationWithOptions({
      signingAlgo,
      includeSpkiFingerprint,
    });
  }

  protected override requestGatewayAttestation(
    request: Request,
    capturePeerSpkiFingerprint: boolean,
  ): Promise<GatewayAttestationHttpResponse> {
    return requestGatewayAttestation(request, capturePeerSpkiFingerprint);
  }
}

function requestGatewayAttestation(
  request: Request,
  capturePeerSpkiFingerprint: boolean,
): Promise<GatewayAttestationHttpResponse> {
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
          const certificate = capturePeerSpkiFingerprint
            ? peerCertificate(incoming.socket as TLSSocket)
            : undefined;
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
