"""NEAR AI Cloud evidence retrieval and local signer selection."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from pydantic import ValidationError

from ..schemas import (
    CloudCompletionSignatureSchema,
    CloudGatewayAttestationResponseSchema,
    CloudGatewayAttestationSchema,
    CloudModelAttestationResponseSchema,
    CloudModelAttestationSchema,
    CloudUnavailableSignatureSchema,
)
from ..types.attestation_common import SigningAlgo, SigningIdentity
from ..types.attestation_gateway import GatewayAttestation
from ..types.attestation_model import ModelAttestation
from ..types.chat import (
    CompletionSignature,
    CompletionSignatureReference,
)
from ..types.cloud_api import (
    DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    NO_ALIASING_HEADER,
    FetchedGatewayAttestation,
    FetchedModelAttestation,
    FetchedModelAttestations,
)
from ..types.verification import (
    GatewayClientBinding,
    ModelClientBinding,
)
from ..utils.common import generate_nonce, hex_to_bytes
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
)
from ..utils.fetch import fetch as default_fetch


SIGNATURE_RESPONSE_FIELDS = {
    'text',
    'signature',
    'signing_address',
    'signing_algo',
    'signature_kind',
}

__all__ = ['AttestationClient', 'find_model_attestation_for_signature']


@dataclass(frozen=True)
class _CloudApiJsonResponse:
    json: object
    peer_spki_fingerprint: str | None


class AttestationClient:
    """Asynchronous NEAR AI Cloud client for evidence and signature retrieval.

    The client owns the Cloud API credentials and base URL. Its methods create
    a fresh nonce for every attestation request; they do not send completion
    requests or retain completion data.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    ) -> None:
        self._api_key = api_key
        self._base_url = _validate_base_url(base_url)

    async def fetch_model_attestations(
        self,
        model: str,
        *,
        signing_algo: SigningAlgo | None = None,
        signing_address: str | None = None,
    ) -> FetchedModelAttestations:
        """Fetch the current NEAR model evidence with a fresh client nonce."""

        if signing_address is not None:
            _validate_input_signing_address(
                signing_address,
                signing_algo,
                'signing_address',
            )
        nonce = generate_nonce()
        query: dict[str, str] = {
            'model': model,
            'provider': 'near',
            'nonce': nonce,
            'include_tls_fingerprint': 'false',
        }
        if signing_algo is not None:
            query['signing_algo'] = signing_algo
        if signing_address is not None:
            query['signing_address'] = signing_address
        response = await _get_cloud_api_json(
            self._api_key,
            _endpoint(self._base_url, 'attestation/report', query),
            'model_attestation',
            extra_headers={NO_ALIASING_HEADER: 'true'},
        )
        attestations = _decode_model_attestation_report(response.json)
        for attestation in attestations:
            _require_matching_api_nonce(attestation.nonce, nonce, 'model_attestation')
        return FetchedModelAttestations(
            attestations=attestations,
            client_binding=ModelClientBinding(nonce=nonce),
        )

    async def fetch_model_attestation_for_signature(
        self,
        model: str,
        signature: CompletionSignatureReference,
    ) -> FetchedModelAttestation:
        """Fetch and select evidence for a ``provider_tee`` completion signature."""

        _require_provider_signature(signature)
        fetched = await self.fetch_model_attestations(
            model,
            signing_algo=signature.signer.signing_algo,
            signing_address=signature.signer.signing_address,
        )
        return FetchedModelAttestation(
            attestation=_find_model_attestation_for_signer(
                fetched.attestations, signature.signer
            ),
            client_binding=fetched.client_binding,
        )

    async def fetch_gateway_attestation(
        self,
        *,
        signing_algo: SigningAlgo | None = None,
        include_spki_fingerprint: bool = True,
    ) -> FetchedGatewayAttestation:
        """Fetch Gateway evidence, optionally including its TLS fingerprint."""

        nonce = generate_nonce()
        query = {
            'nonce': nonce,
            'include_tls_fingerprint': str(include_spki_fingerprint).lower(),
        }
        if signing_algo is not None:
            query['signing_algo'] = signing_algo
        response = await _get_cloud_api_json(
            self._api_key,
            _endpoint(
                self._base_url,
                'attestation/report',
                query,
            ),
            'gateway_attestation',
            capture_peer_spki=include_spki_fingerprint,
        )
        attestation = _decode_gateway_attestation_report(response.json)
        response_includes_spki_fingerprint = attestation.spki_fingerprint is not None
        if response_includes_spki_fingerprint != include_spki_fingerprint:
            raise api_failure(
                'api.invalid_response',
                {
                    'path': 'gateway_attestation.tls_cert_fingerprint',
                    'expected': ('present' if include_spki_fingerprint else 'missing'),
                    'actual': (
                        'present' if response_includes_spki_fingerprint else 'missing'
                    ),
                },
            )
        _require_matching_api_nonce(attestation.nonce, nonce, 'gateway_attestation')
        return FetchedGatewayAttestation(
            attestation=attestation,
            client_binding=GatewayClientBinding(
                nonce=nonce,
                spki_fingerprint=response.peer_spki_fingerprint,
            ),
        )

    async def fetch_completion_signature(
        self,
        completion_id: str,
        *,
        signing_algo: SigningAlgo | None = None,
    ) -> CompletionSignature:
        """Fetch one completion signature or raise an ``ApiError`` if unavailable."""

        query: dict[str, str] = {}
        if signing_algo is not None:
            query['signing_algo'] = signing_algo
        response = await _get_cloud_api_json(
            self._api_key,
            _endpoint(
                self._base_url,
                f'signature/{quote(completion_id, safe="")}',
                query,
            ),
            'completion_signature',
        )
        return _decode_completion_signature(response.json)


def find_model_attestation_for_signature(
    attestations: tuple[ModelAttestation, ...] | list[ModelAttestation],
    signature: CompletionSignatureReference,
) -> ModelAttestation:
    """Select the sole model attestation advertised by a provider signature."""

    _require_provider_signature(signature)
    return _find_model_attestation_for_signer(attestations, signature.signer)


async def _get_cloud_api_json(
    api_key: str,
    url: str,
    resource: str,
    *,
    capture_peer_spki: bool = False,
    extra_headers: Mapping[str, str] | None = None,
) -> _CloudApiJsonResponse:
    headers = {'authorization': _authorization_header(api_key)}
    if extra_headers is not None:
        headers.update(extra_headers)
    try:
        response = await default_fetch(
            url,
            headers=headers,
            _capture_peer_spki=capture_peer_spki,
        )
    except Exception as error:
        raise api_failure(
            'api.transport_failed',
            {'resource': resource, 'reason': 'request'},
            retryable=True,
            cause=error,
        ) from error
    if not response.ok:
        raise api_failure(
            'api.http_status',
            {'resource': resource, 'status': response.status},
            retryable=_is_retryable_status(response.status, resource),
        )
    try:
        json_body = json.loads(response.text())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise api_failure(
            'api.invalid_json', {'resource': resource}, cause=error
        ) from error
    return _CloudApiJsonResponse(
        json=json_body,
        peer_spki_fingerprint=response.peer_spki_fingerprint,
    )


def _authorization_header(api_key: str) -> str:
    value = f'Bearer {api_key}'
    if any(byte != 0x09 and (byte < 0x20 or byte == 0x7F) for byte in value.encode()):
        raise _invalid_input(
            'api_key',
            'invalid_header_value',
            expected='an HTTP header value',
        )
    return value


def _decode_model_attestation_report(value: object) -> tuple[ModelAttestation, ...]:
    try:
        report = CloudModelAttestationResponseSchema.model_validate(value)
    except ValidationError as error:
        _raise_invalid_wire_response(
            error,
            root='model attestation report',
            nested_record_field='model_attestations',
        )
    return tuple(
        _map_model_attestation(raw, f'model_attestations[{index}]')
        for index, raw in enumerate(report.model_attestations)
    )


def _decode_gateway_attestation_report(value: object) -> GatewayAttestation:
    try:
        report = CloudGatewayAttestationResponseSchema.model_validate(value)
    except ValidationError as error:
        _raise_invalid_wire_response(
            error,
            root='gateway attestation report',
            nested_record_field='gateway_attestation',
        )
    return _map_gateway_attestation(report.gateway_attestation, 'gateway_attestation')


def _map_model_attestation(
    raw: CloudModelAttestationSchema, label: str
) -> ModelAttestation:
    return ModelAttestation(
        nonce=_validate_api_nonce(raw.request_nonce, f'{label}.request_nonce'),
        signer=_api_signer(raw.signing_algo, raw.signing_address, label),
        intel_quote=raw.intel_quote,
        event_log=raw.event_log,
        app_compose=raw.info.tcb_info.app_compose,
        reported_quote_data=raw.report_data,
        nvidia_payload=raw.nvidia_payload,
    )


def _map_gateway_attestation(
    raw: CloudGatewayAttestationSchema, label: str
) -> GatewayAttestation:
    return GatewayAttestation(
        nonce=_validate_api_nonce(raw.request_nonce, f'{label}.request_nonce'),
        signer=_api_signer(raw.signing_algo, raw.signing_address, label),
        intel_quote=raw.intel_quote,
        event_log=raw.event_log,
        app_compose=raw.info.tcb_info.app_compose,
        spki_fingerprint=raw.tls_cert_fingerprint,
        reported_quote_data=raw.report_data,
    )


def _decode_completion_signature(value: object) -> CompletionSignature:
    if isinstance(value, dict) and not (SIGNATURE_RESPONSE_FIELDS & set(value)):
        try:
            unavailable = CloudUnavailableSignatureSchema.model_validate(value)
        except ValidationError as error:
            _raise_invalid_wire_response(error, root='signature')
        raise api_failure(
            'api.completion_signature_unavailable',
            {
                'providerErrorCode': unavailable.error_code,
                'providerMessage': unavailable.message,
            },
        )
    try:
        raw = CloudCompletionSignatureSchema.model_validate(value)
    except ValidationError as error:
        _raise_invalid_wire_response(error, root='signature')
    return CompletionSignature(
        kind=raw.signature_kind,
        signed_text=raw.text,
        signature=raw.signature,
        signer=_api_signer(raw.signing_algo, raw.signing_address, 'signature'),
    )


def _raise_invalid_wire_response(
    error: ValidationError,
    *,
    root: str,
    nested_record_field: str | None = None,
) -> NoReturn:
    issue = error.errors(include_url=False)[0]
    path = _wire_error_path(root, issue, nested_record_field)
    raise _invalid_response(path, issue['msg'], issue.get('input'), error) from error


def _wire_error_path(
    root: str, issue: dict[str, object], nested_record_field: str | None
) -> str:
    location = issue['loc']
    if not isinstance(location, tuple):
        return root
    if (
        nested_record_field is not None
        and location[:1] == (nested_record_field,)
        and (
            len(location) > 1
            or (
                nested_record_field == 'gateway_attestation'
                and issue.get('type') != 'missing'
            )
        )
    ):
        return _format_api_path(location)
    nested = _format_api_path(location)
    return root if not nested else f'{root}.{nested}'


def _format_api_path(location: tuple[object, ...]) -> str:
    path = ''
    for part in location:
        if isinstance(part, int):
            path = f'{path}[{part}]'
        elif path:
            path = f'{path}.{part}'
        else:
            path = str(part)
    return path


def _api_signer(algorithm: SigningAlgo, address: str, label: str) -> SigningIdentity:
    _validate_api_signing_address(address, algorithm, f'{label}.signing_address')
    return SigningIdentity(signing_algo=algorithm, signing_address=address)


def _find_model_attestation_for_signer(
    attestations: tuple[ModelAttestation, ...] | list[ModelAttestation],
    signer: SigningIdentity,
) -> ModelAttestation:
    requested_signing_address = _validate_input_signer(
        signer,
        'signature.signer',
    )
    matches: list[ModelAttestation] = []
    for index, attestation in enumerate(attestations):
        attestation_signing_address = _validate_input_signer(
            attestation.signer,
            f'attestations[{index}].signer',
        )
        if (
            attestation.signer.signing_algo == signer.signing_algo
            and attestation_signing_address == requested_signing_address
        ):
            matches.append(attestation)
    if not matches:
        raise api_failure('api.model_attestation_signer_not_found')
    if len(matches) != 1:
        raise api_failure(
            'api.ambiguous_model_attestation_signer',
            {'matchingCount': len(matches), 'totalCount': len(attestations)},
        )
    return matches[0]


def _require_provider_signature(signature: CompletionSignatureReference) -> None:
    if signature.kind != 'provider_tee':
        raise _invalid_input(
            'signature.kind',
            'unsupported_value',
            expected='provider_tee',
            actual=signature.kind,
        )
    _validate_input_signer(signature.signer, 'signature.signer')


def _endpoint(base_url: str, path: str, query: Mapping[str, str]) -> str:
    parsed = urlsplit(base_url)
    normalized_path = f'{parsed.path.rstrip("/")}/{path}'
    return urlunsplit(
        (parsed.scheme, parsed.netloc, normalized_path, urlencode(query), '')
    )


def _validate_base_url(base_url: str) -> str:
    try:
        parsed = urlsplit(base_url)
        _ = parsed.port
    except (TypeError, ValueError):
        raise _invalid_base_url() from None
    if (
        parsed.scheme not in {'http', 'https'}
        or not parsed.netloc
        or parsed.hostname is None
    ):
        raise _invalid_base_url()
    return base_url


def _invalid_base_url() -> ApiError:
    return _invalid_input(
        'base_url',
        'invalid_url',
        expected='an absolute HTTP(S) URL',
    )


def _validate_input_signer(signer: SigningIdentity, field: str) -> bytes:
    return _validate_input_signing_address(
        signer.signing_address,
        signer.signing_algo,
        f'{field}.signing_address',
    )


def _validate_input_signing_address(
    address: str,
    algorithm: SigningAlgo | None,
    field: str,
) -> bytes:
    address_bytes = _input_hex_to_bytes(address, field)
    if algorithm is None:
        valid_lengths = (20, 32)
        expected = 'a 20- or 32-byte hexadecimal signing address'
    else:
        expected_length = 20 if algorithm == 'ecdsa' else 32
        valid_lengths = (expected_length,)
        expected = f'{expected_length}-byte hexadecimal signing address'
    if len(address_bytes) not in valid_lengths:
        raise _invalid_input(
            field,
            'wrong_length',
            expected=expected,
            actual=f'{len(address_bytes)} bytes',
        )
    return address_bytes


def _input_hex_to_bytes(value: str, field: str) -> bytes:
    try:
        return hex_to_bytes(value, field)
    except VerificationError as error:
        raise _invalid_input(field, 'invalid_hex') from error


def _validate_api_signing_address(
    address: str, algorithm: SigningAlgo, label: str
) -> None:
    expected_bytes = 20 if algorithm == 'ecdsa' else 32
    if len(_api_hex_to_bytes(address, label)) != expected_bytes:
        raise _invalid_response(
            label, f'{expected_bytes}-byte hexadecimal signing address', address
        )


def _validate_api_nonce(value: str, label: str) -> str:
    if len(_api_hex_to_bytes(value, label)) != 32:
        raise _invalid_response(label, '32-byte hexadecimal nonce', value)
    return value


def _api_hex_to_bytes(value: str, label: str) -> bytes:
    try:
        return hex_to_bytes(value, label)
    except VerificationError as error:
        raise _invalid_response(label, 'hexadecimal text', value, error) from error


def _require_matching_api_nonce(reported: str, requested: str, resource: str) -> None:
    if _api_hex_to_bytes(reported, f'{resource}.request_nonce') == hex_to_bytes(
        requested, 'nonce'
    ):
        return
    raise api_failure('api.nonce_mismatch', {'resource': resource})


def _is_retryable_status(status: int, resource: str) -> bool:
    return (
        (resource == 'completion_signature' and status == 404)
        or status in {408, 425, 429}
        or status >= 500
    )


def _invalid_response(
    path: str,
    expected: str,
    value: object,
    cause: BaseException | None = None,
) -> ApiError:
    return api_failure(
        'api.invalid_response',
        {'path': path, 'expected': expected, 'actual': _describe_value(value)},
        cause=cause,
    )


def _invalid_input(
    field: str,
    reason: str,
    *,
    expected: str | None = None,
    actual: str | None = None,
) -> ApiError:
    details: dict[str, object] = {'field': field, 'reason': reason}
    if expected is not None:
        details['expected'] = expected
    if actual is not None:
        details['actual'] = actual
    return api_failure('api.invalid_input', details)


def _describe_value(value: object) -> str:
    if value is None:
        return 'null'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, dict):
        return 'object'
    return type(value).__name__
