import { fetchIntelTdxVerificationData } from '../utils/intel';
import { DomainAttestation } from '../types/attestation-domain';
import { VerificationError } from '../utils/errors';
import { hexToBuffer } from '../utils/common';
import { IntelTdxVerificationData } from '../types/intel';
import { type X509Certificate } from 'crypto';
import { getComposeFromTcbInfo, verifyCompose } from './attestation-common';
import { TIMEOUT } from '../utils/consts';

/**
 * Verify domain attestation.
 * Note: This function is only available in Node.js environment
 */
export async function verifyDomainAttestation(attestation: DomainAttestation) {
  const verificationData = await fetchIntelTdxVerificationData(
    attestation.intel_quote,
  );
  await verifyIntelTdxForDomain(
    verificationData,
    attestation.domain,
    attestation.cert,
    attestation.acmeAccount,
    attestation.sha256sum,
  );

  await verifyCompose(getComposeFromTcbInfo(attestation.info.tcb_info));

  const liveCert = await fetchLiveCertificate(attestation.domain);
  await verifyLiveCertificate(liveCert, attestation.cert);
}

async function verifyIntelTdxForDomain(
  verificationData: IntelTdxVerificationData,
  domain: string,
  cert: string,
  acmeAccount: string,
  sha256sum: string,
) {
  if (!verificationData.quote.verified) {
    throw new VerificationError('Intel quote not verified');
  }

  await verifyIntelQuteReportDataForDomain(
    verificationData.quote.body.reportdata,
    domain,
    cert,
    acmeAccount,
    sha256sum,
  );
}

async function verifyIntelQuteReportDataForDomain(
  reportData: string,
  domain: string,
  cert: string,
  acmeAccount: string,
  sha256sum: string,
) {
  const crypto = await import('crypto');

  const certHash = crypto.createHash('sha256').update(cert).digest();
  const acmeAccountHash = crypto
    .createHash('sha256')
    .update(acmeAccount)
    .digest();

  const expectedSha256sumFile =
    `${acmeAccountHash.toString('hex')}  acme-account.json\n` +
    `${certHash.toString('hex')}  cert-${domain}.pem\n`;

  const expectedSha256sum = crypto
    .createHash('sha256')
    .update(expectedSha256sumFile)
    .digest();

  const reportDataRaw = hexToBuffer(reportData);

  const embeddedSha256sum = reportDataRaw.subarray(0, 32);
  const embeddedRemaining = reportDataRaw.subarray(32);

  const sha256sumFileMatched = expectedSha256sumFile === sha256sum;

  if (!sha256sumFileMatched) {
    throw new VerificationError('sha256sum file mismatching');
  }

  const sha256sumMatched = embeddedSha256sum.equals(expectedSha256sum);

  if (!sha256sumMatched) {
    throw new VerificationError('sha256sum mismatching');
  }

  const embeddedRemainingMatched = embeddedRemaining.equals(Buffer.alloc(32));

  if (!embeddedRemainingMatched) {
    throw new VerificationError('Embedded remaining bytes mismatching');
  }
}

async function verifyLiveCertificate(liveCert: X509Certificate, cert: string) {
  const certChain = await parseCertificateChain(cert);

  if (certChain.length < 2) {
    throw new VerificationError('Unexpected length of certificate chain');
  }

  const rootCert = certChain[certChain.length - 1];
  const leafCert = certChain[0];

  verifyCertificateChain(certChain);
  verifyCertificateRoot(rootCert);
  verifyCertificateLeaf(leafCert);

  await verifyCertificateFingerprint(leafCert, liveCert);
}

function verifyCertificateChain(certChain: X509Certificate[]) {
  for (let i = 0; i < certChain.length - 1; i++) {
    const cert = certChain[i];
    const issuerCert = certChain[i + 1];

    const isVerified = cert.verify(issuerCert.publicKey);
    const isIssuerMatched = cert.issuer === issuerCert.subject;

    if (!isVerified) {
      throw new VerificationError(
        `Certificate chain verification failed: Certificate ${i} signature verification failed`,
      );
    }

    if (!isIssuerMatched) {
      throw new VerificationError(
        `Certificate chain verification failed: Certificate ${i} issuer '${cert.issuer}' does not match next certificate subject '${issuerCert.subject}'`,
      );
    }
  }
}

function verifyCertificateRoot(cert: X509Certificate) {
  const trustedRootIssuers = [
    'C=US\nO=Internet Security Research Group\nCN=ISRG Root X1',
    'C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3',
  ];

  const isTrusted =
    cert.issuer === cert.subject
      ? cert.verify(cert.publicKey)
      : trustedRootIssuers.includes(cert.issuer);

  if (!isTrusted) {
    throw new VerificationError(
      `Certificate verification failed: Root certificate is not trusted (issuer: ${cert.issuer})`,
    );
  }
}

function verifyCertificateLeaf(cert: X509Certificate) {
  const currentTime = new Date();

  if (new Date(cert.validFrom) > currentTime) {
    throw new VerificationError(
      `Failed to verify leaf certificate: Certificate is not yet valid (valid from: ${cert.validFrom})`,
    );
  }

  if (new Date(cert.validTo) < currentTime) {
    throw new VerificationError(
      `Failed to verify leaf certificate: Certificate has expired (valid to: ${cert.validTo})`,
    );
  }
}

async function verifyCertificateFingerprint(
  cert1: X509Certificate,
  cert2: X509Certificate,
) {
  const fingerprint1 = await getCertificateFingerprint(cert1);
  const fingerprint2 = await getCertificateFingerprint(cert2);

  if (fingerprint1 !== fingerprint2) {
    throw new VerificationError('Certificate fingerprint mismatching');
  }
}

async function parseCertificateChain(cert: string): Promise<X509Certificate[]> {
  const crypto = await import('crypto');

  const pemCertificateRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const parsedCertificates: X509Certificate[] = [];

  for (const certificateMatch of cert.matchAll(pemCertificateRegex)) {
    const x509Certificate = new crypto.X509Certificate(certificateMatch[0]);
    parsedCertificates.push(x509Certificate);
  }

  return parsedCertificates;
}

async function getCertificateFingerprint(
  cert: X509Certificate,
): Promise<string> {
  const crypto = await import('crypto');

  const der = cert.raw;
  const hash = crypto.createHash('sha256').update(der).digest('hex');
  // Format as colon-separated uppercase hex (OpenSSL format)
  const fingerprint = hash.toUpperCase().match(/.{2}/g)?.join(':');
  if (!fingerprint) {
    throw new VerificationError('Failed to get certificate fingerprint');
  }
  return fingerprint;
}

async function fetchLiveCertificate(
  domain: string,
  port: number = 443,
): Promise<X509Certificate> {
  const crypto = await import('crypto');
  const tls = await import('tls');

  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, domain, {
      servername: domain,
      timeout: TIMEOUT,
      rejectUnauthorized: false, // We're just fetching the cert, not verifying it
    });

    socket.on('secureConnect', () => {
      try {
        const cert = socket.getPeerX509Certificate();

        if (!cert) {
          reject(new VerificationError('Failed to get certificate'));
          return;
        }

        const pem =
          '-----BEGIN CERTIFICATE-----\n' +
          cert.raw
            .toString('base64')
            .match(/.{1,64}/g)
            ?.join('\n') +
          '\n-----END CERTIFICATE-----';

        resolve(new crypto.X509Certificate(pem));
      } catch (e: unknown) {
        reject(new VerificationError(`Failed to parse certificate`, e));
      } finally {
        socket.end();
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new VerificationError('TLS connection timeout'));
    });

    socket.on('error', (e) => {
      reject(new VerificationError(`TLS connection error`, e));
    });
  });
}
