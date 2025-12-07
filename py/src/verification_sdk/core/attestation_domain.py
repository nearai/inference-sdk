import hashlib
import re
import socket
import ssl
import pydash

from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding

from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
)
from ..types.attestation_domain import DomainAttestation
from ..utils.common import hex_to_bytes
from ..utils.consts import TIMEOUT
from ..utils.errors import VerificationError
from ..utils.intel import fetch_intel_tdx_verification_data


def verify_domain_attestation(attestation: DomainAttestation):
    verification_data = fetch_intel_tdx_verification_data(attestation.intel_quote)

    verify_intel_tdx_for_domain(
        verification_data,
        attestation.domain,
        attestation.cert,
        attestation.acme_account,
        attestation.sha256sum,
    )

    verify_compose(get_compose_from_tcb_info(attestation.info.tcb_info))

    live_cert = fetch_live_certificate(attestation.domain)
    verify_live_certificate(live_cert, attestation.cert)


def verify_intel_tdx_for_domain(
    verification_data: dict,
    domain: str,
    cert: str,
    acme_account: str,
    sha256sum: str,
):
    if not pydash.get(verification_data, "quote.verified"):
        raise VerificationError('Intel quote not verified')

    report_data = pydash.get(verification_data, "quote.body.reportdata")

    if not isinstance(report_data, str):
        raise VerificationError('Bad reportdata')

    verify_intel_quote_report_data_for_domain(
        report_data,
        domain,
        cert,
        acme_account,
        sha256sum,
    )


def verify_intel_quote_report_data_for_domain(
    report_data: str,
    domain: str,
    cert: str,
    acme_account: str,
    sha256sum: str,
):
    cert_hash = hashlib.sha256(cert.encode()).digest()
    acme_account_hash = hashlib.sha256(acme_account.encode()).digest()

    expected_sha256sum_file = (
        f"{acme_account_hash.hex()}  acme-account.json\n"
        f"{cert_hash.hex()}  cert-{domain}.pem\n"
    )

    expected_sha256sum = hashlib.sha256(expected_sha256sum_file.encode()).digest()

    report_data_raw = hex_to_bytes(report_data)

    embedded_sha256sum = report_data_raw[:32]
    embedded_remaining = report_data_raw[32:]

    sha256sum_file_matched = expected_sha256sum_file == sha256sum

    if not sha256sum_file_matched:
        raise VerificationError('sha256sum file mismatching')

    sha256sum_matched = embedded_sha256sum == expected_sha256sum

    if not sha256sum_matched:
        raise VerificationError('sha256sum mismatching')

    embedded_remaining_matched = embedded_remaining == b'\x00' * 32

    if not embedded_remaining_matched:
        raise VerificationError('Embedded remaining bytes mismatching')


def verify_live_certificate(
    live_cert: x509.Certificate,
    cert: str,
):
    cert_chain = parse_certificate_chain(cert)

    if len(cert_chain) < 2:
        raise VerificationError('Unexpected length of certificate chain')

    root_cert = cert_chain[-1]
    leaf_cert = cert_chain[0]

    verify_certificate_chain(cert_chain)
    verify_certificate_root(root_cert)
    verify_certificate_leaf(leaf_cert)

    verify_certificate_fingerprint(leaf_cert, live_cert)


def verify_certificate_chain(cert_chain: list[x509.Certificate]):
    for i in range(len(cert_chain) - 1):
        cert = cert_chain[i]
        issuer_cert = cert_chain[i + 1]

        # Verify certificate signature using issuer's public key
        try:
            hash_alg = cert.signature_hash_algorithm
            issuer_pubkey = issuer_cert.public_key()

            # Verify signature based on public key type
            if isinstance(issuer_pubkey, rsa.RSAPublicKey):
                if hash_alg is not None:
                    issuer_pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        hash_alg,
                    )
                else:
                    issuer_pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                    )
            elif isinstance(issuer_pubkey, ec.EllipticCurvePublicKey):
                if hash_alg is not None:
                    issuer_pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(hash_alg),
                    )
                else:
                    # Default to SHA256 for ECDSA if no hash algorithm specified
                    issuer_pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(hashes.SHA256()),
                    )
            else:
                raise VerificationError(
                    f'Certificate chain verification failed: Certificate {i} unsupported public key type'
                )
            is_verified = True
        except Exception as e:
            is_verified = False
            if isinstance(e, VerificationError):
                raise

        cert_issuer = cert.issuer.rfc4514_string()
        issuer_cert_subject = issuer_cert.subject.rfc4514_string()

        is_issuer_matched = cert_issuer == issuer_cert_subject

        if not is_verified:
            raise VerificationError(
                f'Certificate chain verification failed: Certificate {i} signature verification failed'
            )

        if not is_issuer_matched:
            raise VerificationError(
                f'Certificate chain verification failed: Certificate {i} issuer \'{cert_issuer}\' '
                f'does not match next certificate subject \'{issuer_cert_subject}\''
            )


def verify_certificate_root(cert: x509.Certificate):
    """Verify that the root certificate is trusted."""
    # Note: TypeScript version uses newline-separated format, but Python's rfc4514_string()
    # returns comma-separated format. We'll check both formats for compatibility.
    trusted_root_issuers = [
        'C=US, O=Internet Security Research Group, CN=ISRG Root X1',
        'C=US\nO=Internet Security Research Group\nCN=ISRG Root X1',
        'C=US, O=Digital Signature Trust Co., CN=DST Root CA X3',
        'C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3',
    ]

    cert_issuer = cert.issuer.rfc4514_string()
    cert_subject = cert.subject.rfc4514_string()

    is_self_signed = cert_issuer == cert_subject

    if is_self_signed:
        try:
            hash_alg = cert.signature_hash_algorithm
            pubkey = cert.public_key()

            if isinstance(pubkey, rsa.RSAPublicKey):
                if hash_alg is not None:
                    pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        hash_alg,
                    )
                else:
                    pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                    )
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                if hash_alg is not None:
                    pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(hash_alg),
                    )
                else:
                    pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(hashes.SHA256()),
                    )
            is_trusted = True
        except Exception:
            is_trusted = False
    else:
        is_trusted = cert_issuer in trusted_root_issuers

    if not is_trusted:
        raise VerificationError(
            f'Certificate verification failed: Root certificate is not trusted (issuer: {cert_issuer})'
        )


def verify_certificate_leaf(cert: x509.Certificate):
    from datetime import datetime

    current_time = datetime.now()

    if cert.not_valid_before > current_time:
        raise VerificationError(
            f'Failed to verify leaf certificate: Certificate is not yet valid '
            f'(valid from: {cert.not_valid_before_utc})'
        )

    if cert.not_valid_after < current_time:
        raise VerificationError(
            f'Failed to verify leaf certificate: Certificate has expired '
            f'(valid to: {cert.not_valid_after_utc})'
        )


def verify_certificate_fingerprint(cert1: x509.Certificate, cert2: x509.Certificate):
    fingerprint1 = get_certificate_fingerprint(cert1)
    fingerprint2 = get_certificate_fingerprint(cert2)

    if fingerprint1 != fingerprint2:
        raise VerificationError('Certificate fingerprint mismatching')


def parse_certificate_chain(cert: str) -> list[x509.Certificate]:
    pem_certificate_regex = re.compile(
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'
    )
    parsed_certificates = []

    for certificate_match in pem_certificate_regex.finditer(cert):
        x509_certificate = x509.load_pem_x509_certificate(
            certificate_match.group(0).encode()
        )
        parsed_certificates.append(x509_certificate)

    return parsed_certificates


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(encoding=Encoding.DER)
    hash_digest = hashlib.sha256(der).digest()
    hash_hex = hash_digest.hex().upper()
    # Format as colon-separated uppercase hex (OpenSSL format)
    fingerprint = ':'.join(hash_hex[i:i+2] for i in range(0, len(hash_hex), 2))
    if not fingerprint:
        raise VerificationError('Failed to get certificate fingerprint')
    return fingerprint


def fetch_live_certificate(domain: str, port: Optional[int] = 443) -> x509.Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We're just fetching the cert, not verifying it

    try:
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    raise VerificationError('Failed to get certificate')

                cert = x509.load_der_x509_certificate(cert_der)
                return cert
    except socket.timeout:
        raise VerificationError('TLS connection timeout')
    except Exception as e:
        raise VerificationError(f'TLS connection error: {str(e)}') from e

