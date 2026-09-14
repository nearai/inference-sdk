import type { Buffer } from 'node:buffer';
import { createHash, X509Certificate } from 'node:crypto';
import * as https from 'node:https';
import type { IncomingHttpHeaders } from 'node:http';
import { Readable } from 'node:stream';
import {
  checkServerIdentity,
  type PeerCertificate,
  type TLSSocket,
} from 'node:tls';
import {
  CloudApiClient,
  type GatewayAttestationHttpResponse,
} from '../core/cloud-api';
import type {
  FetchedGatewayAttestation,
  NodeFetchGatewayAttestationParams,
} from '../types/cloud-api';
import type { CreatePinnedGatewayFetchParams } from '../types/node';
import { requireByteLength } from '../utils/common';
import { VerificationError } from '../utils/errors';

type RequestHttpsParams = {
  readonly request: Request;
  readonly capturePeerSpkiFingerprint?: boolean;
  readonly expectedSpkiFingerprint?: Uint8Array;
};

type VerifyPinnedPeerParams = {
  readonly hostname: string;
  readonly certificate: PeerCertificate;
  readonly expectedSpkiFingerprint: Uint8Array;
};

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
    if (new URL(request.url).protocol !== 'https:') {
      return super.requestGatewayAttestation(
        request,
        capturePeerSpkiFingerprint,
      );
    }
    return requestHttps({ request, capturePeerSpkiFingerprint });
  }
}

/**
 * Create a Fetch-compatible HTTPS transport that requires each TLS peer to
 * present the SPKI authenticated by a Gateway attestation.
 *
 * Standard certificate-chain and hostname verification still run first. The
 * transport creates a new native HTTPS request for each call, so it does not
 * require reuse of the connection that returned the attestation.
 */
export function createPinnedGatewayFetch({
  spkiFingerprint,
}: CreatePinnedGatewayFetchParams): typeof globalThis.fetch {
  const expectedSpkiFingerprint = requireByteLength({
    value: spkiFingerprint,
    byteLength: 32,
    label: 'spkiFingerprint',
  });

  return async (input, init) => {
    const request = new Request(input, init);
    if (new URL(request.url).protocol !== 'https:') {
      throw new TypeError('Pinned Gateway fetch requires an HTTPS URL');
    }
    return (await requestHttps({ request, expectedSpkiFingerprint })).response;
  };
}

function requestHttps({
  request,
  capturePeerSpkiFingerprint = false,
  expectedSpkiFingerprint,
}: RequestHttpsParams): Promise<GatewayAttestationHttpResponse> {
  const headers = new Headers(request.headers);
  if (!headers.has('accept-encoding')) {
    headers.set('accept-encoding', 'identity');
  }

  return new Promise((resolve, reject) => {
    const nativeRequest = https.request(
      request.url,
      {
        agent: false,
        method: request.method,
        headers: Object.fromEntries(headers),
        rejectUnauthorized: true,
        signal: request.signal,
        ...(expectedSpkiFingerprint === undefined
          ? {}
          : {
              checkServerIdentity: (
                hostname: string,
                certificate: PeerCertificate,
              ) =>
                verifyPinnedPeer({
                  hostname,
                  certificate,
                  expectedSpkiFingerprint,
                }),
            }),
      },
      (incoming) => {
        try {
          const certificate = capturePeerSpkiFingerprint
            ? peerCertificate(incoming.socket as TLSSocket)
            : undefined;
          const peerSpkiFingerprint =
            certificate === undefined
              ? undefined
              : spkiFingerprintForCertificate(certificate).toString('hex');
          const body = responseBody(incoming.statusCode, incoming);
          resolve({
            response: new Response(body, {
              status: incoming.statusCode ?? 500,
              statusText: incoming.statusMessage,
              headers: responseHeaders(incoming.headers),
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
    if (request.body === null) {
      nativeRequest.end();
      return;
    }
    void request.arrayBuffer().then(
      (body) => nativeRequest.end(new Uint8Array(body)),
      (cause: unknown) =>
        nativeRequest.destroy(
          cause instanceof Error
            ? cause
            : new Error('Failed to read the request body'),
        ),
    );
  });
}

function verifyPinnedPeer({
  hostname,
  certificate,
  expectedSpkiFingerprint,
}: VerifyPinnedPeerParams): Error | undefined {
  const identityError = checkServerIdentity(hostname, certificate);
  if (identityError !== undefined) {
    return identityError;
  }
  try {
    const actualSpkiFingerprint = spkiFingerprintForCertificate(
      new X509Certificate(certificate.raw),
    );
    if (actualSpkiFingerprint.equals(expectedSpkiFingerprint)) {
      return undefined;
    }
    return new VerificationError({
      code: 'binding.spki_fingerprint_mismatch',
    });
  } catch (cause) {
    return cause instanceof Error
      ? cause
      : new Error('Failed to read the TLS peer certificate');
  }
}

function spkiFingerprintForCertificate(certificate: X509Certificate): Buffer {
  return createHash('sha256')
    .update(
      certificate.publicKey.export({
        type: 'spki',
        format: 'der',
      }),
    )
    .digest();
}

function responseBody(
  statusCode: number | undefined,
  incoming: Readable,
): ReadableStream<Uint8Array> | null {
  if (statusCode === 204 || statusCode === 205 || statusCode === 304) {
    return null;
  }
  return Readable.toWeb(incoming) as ReadableStream<Uint8Array>;
}

function responseHeaders(headers: IncomingHttpHeaders): Headers {
  const result = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        result.append(name, item);
      }
      continue;
    }
    result.set(name, value);
  }
  return result;
}

function peerCertificate(socket: TLSSocket): X509Certificate | undefined {
  const certificate = socket.getPeerX509Certificate();
  if (certificate !== undefined) {
    return certificate;
  }

  const peer = socket.getPeerCertificate(true);
  return peer.raw === undefined ? undefined : new X509Certificate(peer.raw);
}
