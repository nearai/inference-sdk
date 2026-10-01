"""Experimental direct endpoint evidence retrieval, without Gateway routing."""

from collections.abc import Mapping
from dataclasses import replace

from pydantic import ValidationError

from ..schemas import (
    DirectAttestationReportSchema,
    DirectCompletionSignatureSchema,
    DirectModelAttestationSchema,
)
from ..types.attestation_common import SigningAlgo
from ..types.chat import CompletionSignature
from ..types.direct import (
    DirectClientBinding,
    DirectModelAttestation,
    FetchedDirectModelAttestations,
)
from ..utils.common import generate_nonce
from .cloud_api import (
    _ApiClient,
    _decode_completion_signature,
    _endpoint,
    _invalid_response,
    _map_model_attestation,
    _map_ohttp_attestation,
    _raise_invalid_wire_response,
    _require_matching_api_nonce,
    _validate_input_signing_address,
)


class DirectAttestationClient(_ApiClient):
    """Experimental provider client. Use Gateway clients for production."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(api_key, base_url=base_url, headers=headers)

    async def fetch_model_attestations(
        self,
        *,
        signing_algo: SigningAlgo | None = None,
        signing_address: str | None = None,
    ) -> FetchedDirectModelAttestations:
        """Fetch the serving report and every supplied instance with a fresh nonce."""

        if signing_address is not None:
            _validate_input_signing_address(
                signing_address, signing_algo, 'signing_address'
            )
        nonce = generate_nonce()
        # Disabled until the endpoint returns every serving CVM.
        # https://github.com/nearai/cloud-api/issues/1087
        query = {'nonce': nonce, 'include_tls_fingerprint': 'false'}
        if signing_algo is not None:
            query['signing_algo'] = signing_algo
        if signing_address is not None:
            query['signing_address'] = signing_address
        response = await self._get_json(
            _endpoint(self._base_url, 'attestation/report', query), 'model_attestation'
        )
        try:
            raw = DirectAttestationReportSchema.model_validate(response.json)
        except ValidationError as error:
            _raise_invalid_wire_response(error, root='direct attestation report')
        root = _map_direct_attestation(raw, 'attestation')
        attestations = tuple(
            _map_direct_attestation(item, f'all_attestations[{index}]')
            for index, item in enumerate(raw.all_attestations)
        )
        # Dataclass equality compares report contents, including opaque event logs.
        # A shared signing identity alone cannot identify the serving report.
        serving_index = next(
            (
                index
                for index, item in enumerate(attestations)
                if replace(item, compose_manager_attestation=None)
                == replace(root, compose_manager_attestation=None)
            ),
            None,
        )
        if serving_index is None:
            raise _invalid_response(
                'all_attestations',
                'array containing the top-level attestation',
                raw.all_attestations,
            )
        # The envelope's manager report belongs to the serving report only.
        if root.compose_manager_attestation is not None:
            attestations = tuple(
                replace(
                    item, compose_manager_attestation=root.compose_manager_attestation
                )
                if index == serving_index
                else item
                for index, item in enumerate(attestations)
            )
        for index, attestation in enumerate(attestations):
            _require_matching_api_nonce(attestation.nonce, nonce, 'model_attestation')
            if attestation.spki_fingerprint is not None:
                raise _invalid_response(
                    f'all_attestations[{index}].tls_cert_fingerprint',
                    'missing',
                    attestation.spki_fingerprint,
                )
        return FetchedDirectModelAttestations(
            serving_attestation=attestations[serving_index],
            attestations=attestations,
            client_binding=DirectClientBinding(nonce=nonce),
            ohttp_attestation=(
                None
                if raw.ohttp_attestation is None
                else _map_ohttp_attestation(raw.ohttp_attestation)
            ),
        )

    @staticmethod
    def _decode_signature(value: object) -> CompletionSignature:
        return _decode_completion_signature(value, DirectCompletionSignatureSchema)


def _map_direct_attestation(
    raw: DirectModelAttestationSchema, label: str
) -> DirectModelAttestation:
    model = _map_model_attestation(raw, label)
    return DirectModelAttestation(
        nonce=model.nonce,
        signer=model.signer,
        intel_quote=model.intel_quote,
        event_log=model.event_log,
        app_compose=model.app_compose,
        reported_quote_data=model.reported_quote_data,
        nvidia_payload=model.nvidia_payload,
        signing_public_key=model.signing_public_key,
        compose_manager_attestation=model.compose_manager_attestation,
        model_name=raw.model_name,
        instance_id=raw.info.instance_id,
        spki_fingerprint=raw.tls_cert_fingerprint,
    )
