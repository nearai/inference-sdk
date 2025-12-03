from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import SignatureAlgorithmOID

from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
)
from ..types.attestation_domain import DomainAttestation
from ..utils.common import hex_to_bytes, json_loads
from ..utils.errors import VerificationError
from ..utils.intel import fetch_intel_tdx_verification_data


def _parse_certificate_chain(cert_chain_pem: str) -> list[x509.Certificate]:
    import re

    pem_certificate_regex = (
        r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
    )
    parsed: list[x509.Certificate] = []
    for match in re.finditer(pem_certificate_regex, cert_chain_pem):
        cert_pem = match.group(0)
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        parsed.append(cert)
    if not parsed:
        raise VerificationError("Certificate chain verification failed: empty chain")
    return parsed


def _verify_certificate_chain(certificates: list[x509.Certificate]) -> None:
    if not certificates:
        raise VerificationError("Certificate chain verification failed: empty chain")

    for index in range(len(certificates) - 1):
        certificate = certificates[index]
        issuer_certificate = certificates[index + 1]

        issuer_public_key = issuer_certificate.public_key()
        signature_algorithm = certificate.signature_algorithm_oid

        if signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA256:
            hash_algorithm = hashes.SHA256()
            padding_algorithm = padding.PKCS1v15()
        elif signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA384:
            hash_algorithm = hashes.SHA384()
            padding_algorithm = padding.PKCS1v15()
        elif signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA512:
            hash_algorithm = hashes.SHA512()
            padding_algorithm = padding.PKCS1v15()
        elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA256:
            hash_algorithm = hashes.SHA256()
            padding_algorithm = None
        elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA384:
            hash_algorithm = hashes.SHA384()
            padding_algorithm = None
        elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA512:
            hash_algorithm = hashes.SHA512()
            padding_algorithm = None
        else:
            hash_algorithm = hashes.SHA256()
            padding_algorithm = (
                padding.PKCS1v15()
                if isinstance(issuer_public_key, rsa.RSAPublicKey)
                else None
            )

        try:
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding_algorithm,
                    hash_algorithm,
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(hash_algorithm),
                )
            else:
                raise VerificationError("Unsupported public key type")
        except Exception as exc:
            raise VerificationError(
                f"Certificate chain verification failed: certificate {index} signature verification failed"
            ) from exc

        if certificate.issuer.rfc4514_string() != issuer_certificate.subject.rfc4514_string():
            raise VerificationError(
                f"Certificate chain verification failed: certificate {index} issuer does not match next certificate subject"
            )


def _is_root_certificate_trusted(root_certificate: x509.Certificate) -> bool:
    trusted_root_ca_issuers = {
        "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
        "C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "CN=DST Root CA X3,O=Digital Signature Trust Co.,C=US",
    }
    issuer_dn = root_certificate.issuer.rfc4514_string()
    subject_dn = root_certificate.subject.rfc4514_string()
    if issuer_dn == subject_dn and issuer_dn in trusted_root_ca_issuers:
        return True
    return issuer_dn in trusted_root_ca_issuers


def _verify_certificate_root(cert: x509.Certificate) -> None:
    if not _is_root_certificate_trusted(cert):
        raise VerificationError(
            f"Certificate verification failed: Root certificate is not trusted (issuer: {cert.issuer.rfc4514_string()})"
        )


def _verify_certificate_leaf(cert: x509.Certificate) -> None:
    current_time = datetime.now(timezone.utc)
    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if not_before > current_time:
        raise VerificationError(
            f"Certificate verification failed: certificate is not yet valid (valid from: {not_before})"
        )
    if not_after < current_time:
        raise VerificationError(
            f"Certificate verification failed: certificate has expired (valid to: {not_after})"
        )


def _get_certificate_fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    hash_hex = sha256(der).hexdigest().upper()
    return ":".join(hash_hex[i : i + 2] for i in range(0, len(hash_hex), 2))


def _fetch_live_certificate(domain: str, port: int = 443) -> x509.Certificate:
    import ssl
    import socket

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((domain, port), timeout=10)
    try:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if not cert_der:
                raise VerificationError("Failed to get certificate from server")
            return x509.load_der_x509_certificate(cert_der, default_backend())
    finally:
        sock.close()


def _verify_certificate(attestation: DomainAttestation) -> None:
    cert_chain = _parse_certificate_chain(attestation.cert)
    if len(cert_chain) < 2:
        raise VerificationError("Unexpected length of certificate chain")

    root_cert = cert_chain[-1]
    leaf_cert = cert_chain[0]

    _verify_certificate_chain(cert_chain)
    _verify_certificate_root(root_cert)
    _verify_certificate_leaf(leaf_cert)

    # Compare fingerprint with live server
    evidence_fingerprint = _get_certificate_fingerprint(leaf_cert)
    live_cert = _fetch_live_certificate(attestation.domain, 443)
    live_fingerprint = _get_certificate_fingerprint(live_cert)
    if evidence_fingerprint != live_fingerprint:
        raise VerificationError("Certificate fingerprint mismatching")


def _verify_dns_caa(domain_name: str, acme_account_uri: str) -> None:
    dns_url = f"https://dns.google/resolve?name={domain_name}&type=CAA"
    try:
        res = requests.get(dns_url, timeout=10)
    except requests.RequestException as exc:
        raise VerificationError("DNS CAA query failed") from exc

    if not res.ok:
        raise VerificationError(
            f"DNS CAA query failed for domain '{domain_name}': {res.status_code} {res.reason}"
        )

    dns_data = res.json()
    records = dns_data.get("Answer", [])
    caa_records = [r for r in records if r.get("type") == 257]
    if not caa_records:
        raise VerificationError(
            f"No CAA records found for domain '{domain_name}' - domain does not have Certificate Authority Authorization configured"
        )

    if not all(acme_account_uri in (r.get("data") or "") for r in caa_records):
        raise VerificationError(
            f"CAA records for domain '{domain_name}' do not authorize ACME account '{acme_account_uri}'"
        )


def _verify_report_data(attestation: DomainAttestation, intel_result: Dict) -> None:
    acme_account_hash = sha256(attestation.acme_account.encode()).hexdigest()
    cert_hash = sha256(attestation.cert.encode()).hexdigest()
    expected_sha256sum_file = (
        f"{acme_account_hash}  acme-account.json\n"
        f"{cert_hash}  cert-{attestation.domain}.pem\n"
    )
    expected_sha256sum = sha256(expected_sha256sum_file.encode()).hexdigest()

    report_data_hex = intel_result["quote"]["body"]["reportdata"]
    report_data = hex_to_bytes(report_data_hex)

    embedded_sha256sum = report_data[:32].hex()
    empty_bytes = report_data[32:].hex()

    if expected_sha256sum_file != attestation.sha256sum:
        raise VerificationError("sha256sum file mismatching")
    if embedded_sha256sum != expected_sha256sum:
        raise VerificationError("sha256sum mismatching")
    if empty_bytes != "0" * 64:
        raise VerificationError("Embedded remaining bytes mismatching")


def verify_domain_attestation(attestation: DomainAttestation) -> None:
    """Verify domain attestation (Intel TDX + compose + certificate + DNS CAA)."""
    if not attestation.domain:
        raise VerificationError(f"Invalid domain: {attestation.domain!r}")

    intel_result = fetch_intel_tdx_verification_data(attestation.intel_quote)

    _verify_report_data(attestation, intel_result)

    compose = get_compose_from_tcb_info(attestation.info.tcb_info)
    verify_compose(compose)

    _verify_certificate(attestation)

    acme_account_data = json_loads(attestation.acme_account)
    acme_account_uri = acme_account_data.get("uri", "")
    if acme_account_uri:
        _verify_dns_caa(attestation.domain, acme_account_uri)


