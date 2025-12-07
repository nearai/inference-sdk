import pytest

from test.common import (
    fetch_attestation_report,
    fetch_domain_attestation,
    generate_request_nonce,
)
from test.context import init_context
from test.types import Context
from verification_sdk import (
    DomainAttestation,
    GatewayAttestation,
    ModelAttestation,
    SigningAlgo,
    verify_domain_attestation,
    verify_gateway_attestation,
    verify_model_attestation,
)


@pytest.mark.asyncio
class TestAttestations:
    @pytest.fixture(scope='class')
    def context(self) -> Context:
        return init_context()

    @pytest.mark.asyncio
    async def test_gateway_attestation_and_model_attestations_ecdsa(
        self, context: Context
    ):
        await self._test_gateway_attestation_and_model_attestations(context, 'ecdsa')

    @pytest.mark.asyncio
    async def test_gateway_attestation_and_model_attestations_ed25519(
        self, context: Context
    ):
        await self._test_gateway_attestation_and_model_attestations(context, 'ed25519')

    @pytest.mark.asyncio
    async def test_domain_attestation(self, context: Context):
        attestation_dict = await fetch_domain_attestation(context['api_domain'])
        attestation = DomainAttestation(**attestation_dict)
        await verify_domain_attestation(attestation)

    async def _test_gateway_attestation_and_model_attestations(
        self,
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

        gateway_attestation_dict = report['gateway_attestation']
        assert gateway_attestation_dict['request_nonce'] == request_nonce
        assert gateway_attestation_dict['signing_algo'] == signing_algo

        gateway_attestation = GatewayAttestation(**gateway_attestation_dict)
        await verify_gateway_attestation(gateway_attestation, context['api_domain'])

        model_attestations_dict = report.get('model_attestations') or []
        for model_attestation_dict in model_attestations_dict:
            assert model_attestation_dict['request_nonce'] == request_nonce
            assert model_attestation_dict['signing_algo'] == signing_algo

            model_attestation = ModelAttestation(**model_attestation_dict)
            await verify_model_attestation(model_attestation)

