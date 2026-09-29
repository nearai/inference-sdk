"""Experimental direct Chat client sharing encryption and capture with the Gateway client."""

from collections.abc import Mapping, Sequence

import httpx

from ..types.attestation_common import SigningAlgo
from ..types.chat import CompletionSignature
from ..types.direct import (
    VerifiedDirectCompletionResult,
    VerifiedDirectModelAttestation,
)
from ..types.e2ee import E2eeModelKey
from ..types.inference_client import DeploymentPolicy, ModelVerificationOptions
from ..utils.common import hex_to_bytes
from ..utils.errors import verification_failure
from ..utils.fetch import FetchResponse
from .attestation_direct import verify_direct_model_attestations
from .chat import _parse_signature_hex, verify_model_response
from .direct_api import DirectAttestationClient
from .inference_client import (
    DEFAULT_CACHE_TIME_TO_LIVE_MS,
    _InferenceEndpoint,
    _VerifiedInferenceClient,
    _VerifiedSession,
)
from .ohttp_attestation import verify_ohttp_key_config
from .pinned_tls import create_pinned_tls_client


class _DirectSessionAttestationClient(DirectAttestationClient):
    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        api_key: str | None,
        headers: Mapping[str, str],
    ) -> None:
        super().__init__(base_url, api_key=api_key, headers=headers)
        self._http_client = client

    async def _fetch(
        self, url: str, *, headers: Mapping[str, str], _capture_peer_spki: bool = False
    ) -> FetchResponse:
        response = await self._http_client.get(url, headers=headers)
        return FetchResponse(
            status=response.status_code, body=response.content, headers=response.headers
        )


class DirectInferenceClient(_VerifiedInferenceClient[VerifiedDirectCompletionResult]):
    """Experimental direct provider client. E2EE defaults to enabled.

    Verifies all supplied reports before Chat and retains the selected signer
    group for response verification. Direct clients are not recommended for production.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        headers: Mapping[str, str] | None = None,
        e2ee: bool = True,
        ohttp: bool = False,
        signing_algo: SigningAlgo = 'ed25519',
        attestation_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        response_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        model_verification: ModelVerificationOptions | None = None,
        deployment_policy: DeploymentPolicy | None = None,
    ) -> None:
        super().__init__(
            api_key,
            base_url=base_url,
            headers=headers,
            e2ee=e2ee,
            ohttp=ohttp,
            signing_algo=signing_algo,
            attestation_cache_time_to_live_ms=attestation_cache_time_to_live_ms,
            response_cache_time_to_live_ms=response_cache_time_to_live_ms,
            model_verification=model_verification,
            deployment_policy=deployment_policy,
        )
        self._attestation_client = DirectAttestationClient(
            base_url, api_key=api_key, headers=self._headers
        )

    async def _create_session(
        self, model: str, *, endpoint: _InferenceEndpoint
    ) -> _VerifiedSession[VerifiedDirectCompletionResult]:
        fetched = await self._attestation_client.fetch_model_attestations(
            signing_algo=self._signing_algo
        )
        verified = await verify_direct_model_attestations(
            fetched,
            policy=self._model_options.policy,
            verifiers=self._get_model_verifiers(model),
        )
        serving_signer = verified.serving_attestation.signer
        key_config = None
        if self._ohttp:
            if fetched.ohttp_attestation is None:
                raise verification_failure('ohttp.attestation_required')
            key_config = verify_ohttp_key_config(
                fetched.ohttp_attestation, serving_signer
            )
        selected = next(
            (
                item
                for item in verified.attestations
                if item.signer.signing_algo == self._signing_algo
                and item.signing_public_key is not None
                and (
                    not self._ohttp
                    or (
                        item.signer.signing_algo == serving_signer.signing_algo
                        and hex_to_bytes(item.signer.signing_address)
                        == hex_to_bytes(serving_signer.signing_address)
                    )
                )
            ),
            None,
        )
        if selected is None or selected.signing_public_key is None:
            raise verification_failure('e2ee.model_public_key_required')
        attestations = tuple(
            item
            for item in verified.attestations
            if item.signer.signing_algo == self._signing_algo
            and hex_to_bytes(item.signer.signing_address)
            == hex_to_bytes(selected.signer.signing_address)
        )
        fingerprints = (
            tuple(
                dict.fromkeys(
                    item.spki_fingerprint
                    for item in attestations
                    if item.spki_fingerprint is not None
                )
            )
            if verified.tls_binding.kind == 'attested'
            else ()
        )
        client = self._http_clients.get(fingerprints)
        if client is None:
            client = self._create_direct_client(fingerprints)
            self._http_clients[fingerprints] = client
        api = _DirectSessionAttestationClient(
            client, self.base_url, self._api_key, self._headers
        )

        def verify_response(
            id: str,
            request_body: bytes,
            response_body: bytes,
            signature: CompletionSignature,
        ) -> VerifiedDirectCompletionResult:
            matching = verify_direct_model_response(
                request_body, response_body, signature, attestations
            )
            return VerifiedDirectCompletionResult(
                id=id, signature=signature, attestations=matching
            )

        return _VerifiedSession(
            E2eeModelKey(
                signing_algo=self._signing_algo, public_key=selected.signing_public_key
            ),
            self._completion_client(client, key_config),
            api,
            verify_response,
        )

    def _create_direct_client(self, fingerprints: tuple[str, ...]) -> httpx.AsyncClient:
        return (
            create_pinned_tls_client(fingerprints)
            if fingerprints
            else httpx.AsyncClient(timeout=None)
        )


def verify_direct_model_response(
    request_body: bytes,
    response_body: bytes,
    signature: CompletionSignature,
    attestations: Sequence[VerifiedDirectModelAttestation],
) -> tuple[VerifiedDirectModelAttestation, ...]:
    """Verify exact response bytes and return every verified report sharing its signer."""

    if signature.kind != 'provider_tee':
        raise verification_failure(
            'signature.kind_mismatch',
            {'expected': 'provider_tee', 'actual': signature.kind},
        )
    address = _parse_signature_hex(
        signature.signer.signing_address, 'signer.signing_address'
    )
    matching = tuple(
        item
        for item in attestations
        if item.signer.signing_algo == signature.signer.signing_algo
        and hex_to_bytes(item.signer.signing_address) == address
    )
    if not matching:
        raise verification_failure('signature.signer_mismatch')
    verify_model_response(request_body, response_body, signature, matching[0])
    return matching
