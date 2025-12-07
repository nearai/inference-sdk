import pydash

from typing import Optional
from cryptography import x509

from ..core.attestation_common import (
    get_compose_from_tcb_info,
    verify_compose,
)
from ..types.attestation_domain import DomainAttestation
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
    verif_live_certificate(live_cert, attestation.cert)


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
    pass


def verif_live_certificate(
    live_cert: x509.Certificate,
    cert: str,
):
    pass


def verify_certificate_chain(cert_chain: list[x509.Certificate]):
    pass


def verify_certificate_root(cert: x509.Certificate):
    pass


def verify_certificate_leaf(cert: x509.Certificate):
    pass


def verify_certificate_fingerprint(cert1: x509.Certificate, cert2: x509.Certificate):
    pass


def parse_certificate_chain(cert: str) -> list[x509.Certificate]:
    pass


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    pass


def fetch_live_certificate(domain: str, port: Optional[int] = 443) -> x509.Certificate:
    pass

