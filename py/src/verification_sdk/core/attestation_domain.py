import hashlib
import re
import socket
import ssl
import pydash

from datetime import datetime, timezone
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
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


async def verify_domain_attestation(attestation: DomainAttestation):
    verification_data = await fetch_intel_tdx_verification_data(attestation.intel_quote)

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
    if not pydash.get(verification_data, 'quote.verified'):
        raise VerificationError('Intel quote not verified')

    report_data = pydash.get(verification_data, 'quote.body.reportdata')

    if not isinstance(report_data, str):
        raise VerificationError('Bad report data')

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
    acme_account_hash = hashlib.sha256(acme_account.encode()).hexdigest()
    cert_hash = hashlib.sha256(cert.encode()).hexdigest()
    expected_sha256sum_file = (
        f"{acme_account_hash}  acme-account.json\n"
        f"{cert_hash}  cert-{domain}.pem\n"
    )
    expected_sha256sum = hashlib.sha256(expected_sha256sum_file.encode()).digest()

    report_data_raw = hex_to_bytes(report_data)

    embedded_sha256sum = report_data_raw[:32]
    embedded_remaining = report_data_raw[32:]

    sha256sum_file_matched = expected_sha256sum_file == sha256sum

    if not sha256sum_file_matched:
        raise VerificationError(
            f"sha256sum file mismatching: expected '{expected_sha256sum_file}', "
            f"actual '{sha256sum}'"
        )

    sha256sum_matched = embedded_sha256sum == expected_sha256sum

    if not sha256sum_matched:
        raise VerificationError(
            f"sha256sum mismatching: expected '{expected_sha256sum.hex()}', "
            f"actual '{embedded_sha256sum.hex()}'"
        )

    embedded_remaining_matched = embedded_remaining == b'\x00' * 32

    if not embedded_remaining_matched:
        raise VerificationError(
            f"Embedded remaining bytes mismatching: expected all zeros, "
            f"actual '{embedded_remaining.hex()}'"
        )


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
    for index in range(len(cert_chain) - 1):
        cert = cert_chain[index]
        issuer_cert = cert_chain[index + 1]

        # Verify signature using issuer's public key
        verify_certificate_signature(cert, issuer_cert.public_key())

        # Verify issuer matches
        issuer_dn = cert.issuer.rfc4514_string()
        subject_dn = issuer_cert.subject.rfc4514_string()

        if issuer_dn != subject_dn:
            raise VerificationError(
                f"Certificate chain verification failed: Certificate {index} issuer "
                f"'{issuer_dn}' does not match next certificate subject '{subject_dn}'"
            )


def verify_certificate_root(cert: x509.Certificate):
    trusted_root_ca_issuers = [
        "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3",
    ]

    try:
        issuer_dn = cert.issuer.rfc4514_string()
        subject_dn = cert.subject.rfc4514_string()

        # Check if issuer is in trusted list (exact match or component match)
        issuer_in_trusted = issuer_dn in trusted_root_ca_issuers
        if not issuer_in_trusted:
            # Try component-based matching
            issuer_components = _extract_dn_components(issuer_dn)
            for trusted_issuer in trusted_root_ca_issuers:
                trusted_components = _extract_dn_components(trusted_issuer)
                if (
                    issuer_components.get("CN") == trusted_components.get("CN")
                    and issuer_components.get("O") == trusted_components.get("O")
                    and issuer_components.get("C") == trusted_components.get("C")
                ):
                    issuer_in_trusted = True
                    break

        if issuer_dn == subject_dn:
            # Self-signed root certificate - verify signature
            try:
                verify_certificate_signature(cert, cert.public_key())
                return
            except Exception:
                # If signature verification fails, still check if issuer is trusted
                if not issuer_in_trusted:
                    raise VerificationError(
                        f"Certificate verification failed: Root certificate is not trusted (issuer: {issuer_dn})"
                    )
        else:
            if not issuer_in_trusted:
                raise VerificationError(
                    f"Certificate verification failed: Root certificate is not trusted (issuer: {issuer_dn})"
                )
    except VerificationError:
        raise
    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception)
            else "Unknown root certificate trust verification error"
        )
        raise VerificationError(
            f"Root certificate trust verification failed: {error_message}"
        ) from error


def verify_certificate_leaf(cert: x509.Certificate):
    """Check certificate validity period."""
    current_time = datetime.now(timezone.utc)
    # Use UTC-aware datetime properties (timezone-aware)
    not_valid_before = cert.not_valid_before_utc
    not_valid_after = cert.not_valid_after_utc

    if not_valid_before > current_time:
        raise VerificationError(
            f"Certificate verification failed: Certificate is not yet valid "
            f"(valid from: {not_valid_before})"
        )

    if not_valid_after < current_time:
        raise VerificationError(
            f"Certificate verification failed: Certificate has expired "
            f"(valid to: {not_valid_after})"
        )

    # Validate public keys
    leaf_certificate_public_key = cert.public_key()
    if not leaf_certificate_public_key:
        raise VerificationError(
            "Certificate verification failed: Unable to extract public key from certificate"
        )


def verify_certificate_fingerprint(cert1: x509.Certificate, cert2: x509.Certificate):
    """Compare certificate fingerprints."""
    fingerprint1 = get_certificate_fingerprint(cert1)
    fingerprint2 = get_certificate_fingerprint(cert2)

    if fingerprint1 != fingerprint2:
        raise VerificationError(
            f"Certificate fingerprint mismatch: "
            f"evidence certificate fingerprint (SHA256): {fingerprint1}, "
            f"live server certificate fingerprint (SHA256): {fingerprint2}"
        )


def parse_certificate_chain(cert: str) -> list[x509.Certificate]:
    """Parse PEM certificate chain into list of X509 certificates."""
    pem_certificate_regex = r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
    parsed_certificates = []

    for certificate_match in re.finditer(pem_certificate_regex, cert):
        try:
            cert_pem = certificate_match.group(0)
            cert_obj = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            parsed_certificates.append(cert_obj)
        except Exception as parse_error:
            raise VerificationError(
                f"Failed to parse certificate from PEM: {parse_error}"
            ) from parse_error

    return parsed_certificates


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get the SHA256 fingerprint of a certificate in OpenSSL format (colon-separated hex, uppercase)."""
    # Get the raw DER encoding of the certificate
    der = cert.public_bytes(encoding=Encoding.DER)
    # Compute SHA256 hash
    hash_obj = hashlib.sha256(der)
    hash_hex = hash_obj.hexdigest().upper()
    # Format as colon-separated uppercase hex (OpenSSL format)
    return ":".join(hash_hex[i : i + 2] for i in range(0, len(hash_hex), 2))


def fetch_live_certificate(domain: str, port: Optional[int] = 443) -> x509.Certificate:
    """Fetch the certificate from a live server via TLS connection."""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Create socket and wrap with SSL
        sock = socket.create_connection((domain, port), timeout=TIMEOUT)
        try:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the peer certificate (leaf certificate)
                cert_der = ssock.getpeercert(binary_form=True)

                if not cert_der:
                    raise VerificationError("Failed to get certificate from server")

                # Convert DER to X509 certificate
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                return cert
        finally:
            sock.close()
    except socket.timeout:
        raise VerificationError("TLS connection timeout")
    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception) else "Unknown TLS connection error"
        )
        raise VerificationError(f"TLS connection failed: {error_message}") from error


def verify_certificate_signature(cert: x509.Certificate, public_key: CertificatePublicKeyTypes):
    signature_algorithm = cert.signature_algorithm_oid

    # Determine hash algorithm from signature algorithm
    if signature_algorithm == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
        hash_algorithm = hashes.SHA256()
        padding_algorithm = padding.PKCS1v15()
    elif signature_algorithm == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384:
        hash_algorithm = hashes.SHA384()
        padding_algorithm = padding.PKCS1v15()
    elif signature_algorithm == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512:
        hash_algorithm = hashes.SHA512()
        padding_algorithm = padding.PKCS1v15()
    elif signature_algorithm == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
        hash_algorithm = hashes.SHA256()
        padding_algorithm = None
    elif signature_algorithm == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384:
        hash_algorithm = hashes.SHA384()
        padding_algorithm = None
    elif signature_algorithm == x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512:
        hash_algorithm = hashes.SHA512()
        padding_algorithm = None
    else:
        # Default to SHA256
        hash_algorithm = hashes.SHA256()
        padding_algorithm = (
            padding.PKCS1v15() if isinstance(public_key, rsa.RSAPublicKey) else None
        )

    # Verify signature
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding_algorithm,
                hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        else:
            raise VerificationError("Unsupported public key type")
    except Exception as e:
        raise VerificationError(f"Certificate signature verification failed") from e


def _extract_dn_components(dn_string: str) -> dict[str, str]:
    """Extract DN components for flexible comparison."""
    components = {}
    # RFC4514 format: "CN=...,O=...,C=..." or "C=US\nO=...\nCN=..."
    # Handle both comma-separated and newline-separated formats
    if "\n" in dn_string:
        parts = dn_string.split("\n")
    else:
        parts = dn_string.split(",")
    for part in parts:
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            components[key.strip()] = value.strip()
    return components

