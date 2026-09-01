import { createHash, X509Certificate } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';
import type { TLSSocket } from 'node:tls';
import {
  AttestationClient as BaseAttestationClient,
  type GatewayAttestationHttpResponse,
} from '../core/cloud-api';

/**
 * Node client that captures the TLS peer for Gateway attestation requests.
 */
export class AttestationClient extends BaseAttestationClient {
  protected override requestGatewayAttestation(
    request: Request,
  ): Promise<GatewayAttestationHttpResponse> {
    return requestGatewayAttestation(request);
  }
}

function requestGatewayAttestation(
  request: Request,
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
