import { fetchIntelTdxVerificationData } from '../utils/intel';
import { DomainAttestation } from '../types/attestation-domain';
import { VerificationError } from '../utils/errors';
import { hexToBuffer } from '../utils/common';
import { createHash, X509Certificate } from 'crypto';
import * as tls from 'tls';
import { IntelTdxVerificationData } from '../types/intel';

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

  const liveCert = await fetchLiveCertificate(attestation.domain);
  verifyLiveCertificate(liveCert, attestation.cert);
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

  verifyIntelQuteReportDataForDomain(
    verificationData.quote.body.reportdata,
    domain,
    cert,
    acmeAccount,
    sha256sum,
  );
}

function verifyIntelQuteReportDataForDomain(
  reportData: string,
  domain: string,
  cert: string,
  acmeAccount: string,
  sha256sum: string,
) {
  const acmeAccountHash = createHash('sha256')
    .update(acmeAccount)
    .digest('hex');
  const certHash = createHash('sha256').update(cert).digest('hex');
  const expectedSha256sumFile =
    `${acmeAccountHash}  acme-account.json\n` +
    `${certHash}  cert-${domain}.pem\n`;
  const expectedSha256sum = createHash('sha256')
    .update(expectedSha256sumFile)
    .digest('hex');

  const reportDataRaw = hexToBuffer(reportData);

  const embeddedSha256sum = reportDataRaw.subarray(0, 32).toString('hex');
  const emptyBytes = reportDataRaw.subarray(32).toString('hex');

  const sha256sumFileMatches = expectedSha256sumFile === sha256sum;
  const sha256sumMatches = embeddedSha256sum === expectedSha256sum;
  const emptyBytesMatches = emptyBytes === '0'.repeat(64);

  if (!sha256sumFileMatches) {
    throw new VerificationError('sha256sum file mismatching');
  }
  if (!sha256sumMatches) {
    throw new VerificationError('sha256sum mismatching');
  }

  if (!emptyBytesMatches) {
    throw new VerificationError('empty bytes mismatching');
  }
}

function verifyLiveCertificate(liveCert: X509Certificate, cert: string) {
  const certChain = parseCertificateChain(cert);

  if (certChain.length < 2) {
    throw new VerificationError('Unexpected length of certificate chain');
  }

  const rootCert = certChain[certChain.length - 1];
  const leafCert = certChain[0];

  verifyCertificateChain(certChain);
  verifyCertificateRoot(rootCert);
  verifyCertificateLeaf(leafCert);

  verifyCertificateFingerprint(leafCert, liveCert);
}

function verifyCertificateChain(certChain: X509Certificate[]) {
  for (let i = 0; i < certChain.length - 1; i++) {
    const cert = certChain[i];
    const issuerCert = certChain[i + 1];

    const isVerified = cert.verify(issuerCert.publicKey);
    const isIssuerMatches = cert.issuer === issuerCert.subject;

    if (!isVerified) {
      throw new VerificationError(
        `Certificate chain verification failed: Certificate ${i} signature verification failed`,
      );
    }

    if (!isIssuerMatches) {
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

function verifyCertificateFingerprint(
  cert1: X509Certificate,
  cert2: X509Certificate,
) {
  const fingerprint1 = getCertificateFingerprint(cert1);
  const fingerprint2 = getCertificateFingerprint(cert2);

  if (fingerprint1 !== fingerprint2) {
    throw new VerificationError('Certificate fingerprint mismatching');
  }
}

function parseCertificateChain(cert: string): X509Certificate[] {
  const pemCertificateRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const parsedCertificates: X509Certificate[] = [];

  for (const certificateMatch of cert.matchAll(pemCertificateRegex)) {
    const x509Certificate = new X509Certificate(certificateMatch[0]);
    parsedCertificates.push(x509Certificate);
  }

  return parsedCertificates;
}

function getCertificateFingerprint(cert: X509Certificate): string {
  const der = cert.raw;
  const hash = createHash('sha256').update(der).digest('hex');
  // Format as colon-separated uppercase hex (OpenSSL format)
  return hash.toUpperCase().match(/.{2}/g)?.join(':') || '';
}

async function fetchLiveCertificate(
  domain: string,
  port: number = 443,
): Promise<X509Certificate> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, domain, {
      servername: domain,
      timeout: 5000,
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

        resolve(new X509Certificate(pem));
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
