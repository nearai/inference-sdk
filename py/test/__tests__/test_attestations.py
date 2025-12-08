import pytest

from verification_sdk import (
    SigningAlgo,
    verify_domain_attestation,
    verify_gateway_attestation,
    verify_model_attestation,
)

from ..common import (
    fetch_attestation_report,
    fetch_domain_attestation,
    generate_request_nonce,
)
from ..context import init_context
from ..types import Context


class TestAttestations:
    @pytest.fixture(scope='class')
    def context(self) -> Context:
        return init_context()

    async def test_gateway_attestation_and_model_attestations_ecdsa(
        self, context: Context
    ):
        await _test_gateway_attestation_and_model_attestations(context, 'ecdsa')

    async def test_gateway_attestation_and_model_attestations_ed25519(
        self, context: Context
    ):
        await _test_gateway_attestation_and_model_attestations(context, 'ed25519')

    async def test_domain_attestation(self, context: Context):
        attestation = await fetch_domain_attestation(context['api_domain'])
        await verify_domain_attestation(attestation)


async def _test_gateway_attestation_and_model_attestations(
    context: Context,
    signing_algo: SigningAlgo,
):
    request_nonce = generate_request_nonce()

    report = await fetch_attestation_report(
        api_url=context['api_url'],
        api_key=context['api_key'],
        model=context['model'],
        request_nonce=request_nonce,
        signing_algo=signing_algo,
    )

    gateway_attestation = report.gateway_attestation
    assert gateway_attestation.request_nonce == request_nonce
    assert gateway_attestation.signing_algo == signing_algo

    await verify_gateway_attestation(gateway_attestation, context['api_domain'])

    for model_attestation in report.model_attestations or []:
        assert model_attestation.request_nonce == request_nonce
        assert model_attestation.signing_algo == signing_algo

        await verify_model_attestation(model_attestation)
