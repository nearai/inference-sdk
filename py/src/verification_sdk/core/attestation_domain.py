import hashlib
import re
import socket
import ssl

from datetime import datetime, timezone
from typing import Optional
from cryptography import x509
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

    await verify_compose(get_compose_from_tcb_info(attestation.info.tcb_info))

    live_cert = fetch_live_certificate(attestation.domain)
    verify_live_certificate(live_cert, attestation.cert)


def verify_intel_tdx_for_domain(
    verification_data: dict,
    domain: str,
    cert: str,
    acme_account: str,
    sha256sum: str,
):
    if not verification_data.get('quote', {}).get('verified'):
        raise VerificationError('Intel quote not verified')

    report_data = verification_data.get('quote', {}).get('body', {}).get('reportdata')

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
        f'{acme_account_hash}  acme-account.json\n{cert_hash}  cert-{domain}.pem\n'
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
            f'Embedded remaining bytes mismatching: expected all zeros, '
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
        next_cert = cert_chain[index + 1]

        verify_certificate_signature(cert, next_cert.public_key())

        cert_issuer_dn = cert.issuer.rfc4514_string()
        next_cert_dn = next_cert.subject.rfc4514_string()

        if cert_issuer_dn != next_cert_dn:
            raise VerificationError(
                f'Certificate chain verification failed: Certificate {index} issuer '
                f"'{cert_issuer_dn}' does not match next certificate subject '{next_cert_dn}'"
            )


def verify_certificate_root(cert: x509.Certificate):
    trusted_root_ca_issuer_dns = [
        'C=US\nO=Internet Security Research Group\nCN=ISRG Root X1',
        'C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3',
    ]

    cert_issuer_dn = cert.issuer.rfc4514_string()

    issuer_in_trusted = is_dn_trusted(trusted_root_ca_issuer_dns, cert_issuer_dn)

    if cert.subject.rfc4514_string() == cert_issuer_dn:
        verify_certificate_signature(cert, cert.public_key())
    elif not issuer_in_trusted:
        raise VerificationError(
            f'Certificate verification failed: Root certificate is not trusted (issuer: {cert_issuer_dn})'
        )


def verify_certificate_leaf(cert: x509.Certificate):
    current_time = datetime.now(timezone.utc)

    not_valid_before = cert.not_valid_before_utc
    not_valid_after = cert.not_valid_after_utc

    if not_valid_before > current_time:
        raise VerificationError(
            f'Certificate verification failed: Certificate is not yet valid '
            f'(valid from: {not_valid_before})'
        )

    if not_valid_after < current_time:
        raise VerificationError(
            f'Certificate verification failed: Certificate has expired '
            f'(valid to: {not_valid_after})'
        )


def verify_certificate_fingerprint(cert1: x509.Certificate, cert2: x509.Certificate):
    fingerprint1 = get_certificate_fingerprint(cert1)
    fingerprint2 = get_certificate_fingerprint(cert2)

    if fingerprint1 != fingerprint2:
        raise VerificationError('Certificate fingerprint mismatching')


def parse_certificate_chain(cert: str) -> list[x509.Certificate]:
    pem_certificate_regex = (
        r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'
    )

    parsed_certificates = []

    for certificate_match in re.finditer(pem_certificate_regex, cert):
        x509_certificate = x509.load_pem_x509_certificate(
            certificate_match.group(0).encode()
        )
        parsed_certificates.append(x509_certificate)

    return parsed_certificates


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(encoding=Encoding.DER)

    hash_obj = hashlib.sha256(der)
    hash_hex = hash_obj.hexdigest().upper()

    # Format as colon-separated uppercase hex (OpenSSL format)
    return ':'.join(hash_hex[i : i + 2] for i in range(0, len(hash_hex), 2))


def fetch_live_certificate(domain: str, port: Optional[int] = 443) -> x509.Certificate:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((domain, port), timeout=TIMEOUT)

        try:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert_der = ssl_sock.getpeercert(binary_form=True)

                if not cert_der:
                    raise VerificationError(
                        f'Failed to get certificate from for domain: {domain}'
                    )

                return x509.load_der_x509_certificate(cert_der)
        finally:
            sock.close()
    except Exception as e:
        raise VerificationError('TLS connection failed') from e


def verify_certificate_signature(
    cert: x509.Certificate, public_key: CertificatePublicKeyTypes
):
    signature_algorithm = cert.signature_algorithm_oid

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
        raise VerificationError(
            f'Unsupported signature algorithm: {signature_algorithm}'
        )

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
            raise VerificationError('Unsupported public key')
    except VerificationError:
        raise
    except Exception as e:
        raise VerificationError('Certificate signature verification failed') from e


def is_dn_trusted(trusted_dns: list[str], dn: str) -> bool:
    dn_components = dn_string_to_components(dn)

    for trusted_dn in trusted_dns:
        trusted_dn_components = dn_string_to_components(trusted_dn)

        trusted_dn_cn = trusted_dn_components.get('CN')
        if not trusted_dn_cn:
            raise VerificationError("Trusted dn must include 'CN' component")

        trusted_dn_o = trusted_dn_components.get('O')
        if not trusted_dn_o:
            raise VerificationError("Trusted dn must include 'O' component")

        trusted_dn_c = trusted_dn_components.get('C')
        if not trusted_dn_c:
            raise VerificationError("Trusted dn must include 'C' component")

        if (
            dn_components.get('CN') == trusted_dn_cn
            and dn_components.get('O') == trusted_dn_o
            and dn_components.get('C') == trusted_dn_c
        ):
            return True

    return False


def dn_string_to_components(dn: str) -> dict[str, str]:
    components = {}

    # Handle both comma-separated and newline-separated formats
    if '\n' in dn:
        parts = dn.split('\n')
    else:
        parts = dn.split(',')

    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            components[key.strip()] = value.strip()

    return components
