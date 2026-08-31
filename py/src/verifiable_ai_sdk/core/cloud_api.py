"""NEAR AI Cloud evidence and completion-signature request helpers."""

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
    CompletionSignatureLookup,
    CompletionSignatureReference,
    SignatureUnavailable,
)
from ..types.cloud_api import (
    DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    NO_ALIASING_HEADER,
    FetchedGatewayAttestation,
    FetchedModelAttestation,
    FetchedModelAttestations,
)
from ..types.verification import (
    GatewayAttestationPolicy,
    GatewayClientBinding,
    ModelClientBinding,
)
from ..utils.common import generate_nonce, hex_to_bytes
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
    verification_failure,
)
from ..utils.fetch import fetch as default_fetch


SIGNATURE_RESPONSE_FIELDS = {
    'text',
    'signature',
    'signing_address',
    'signing_algo',
    'signature_kind',
}


@dataclass(frozen=True)
class _CloudApiJsonResponse:
    json: object
    peer_spki_fingerprint: str | None


async def fetch_model_attestations(
    api_key: str,
    model: str,
    *,
    signing_algo: SigningAlgo | None = None,
    signing_address: str | None = None,
    base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
) -> FetchedModelAttestations:
    """Fetch the current NEAR model evidence with a fresh client nonce."""

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
        api_key,
        _endpoint(base_url, 'attestation/report', query),
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
    api_key: str,
    model: str,
    signature: CompletionSignatureReference,
    *,
    base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
) -> FetchedModelAttestation:
    """Fetch and select evidence for a ``provider_tee`` completion signature."""

    fetched = await fetch_model_attestations(
        api_key,
        model,
        signing_algo=signature.signer.signing_algo,
        signing_address=signature.signer.signing_address,
        base_url=base_url,
    )
    return FetchedModelAttestation(
        attestation=find_model_attestation_for_signature(
            fetched.attestations, signature
        ),
        client_binding=fetched.client_binding,
    )


def find_model_attestation_for_signature(
    attestations: tuple[ModelAttestation, ...] | list[ModelAttestation],
    signature: CompletionSignatureReference,
) -> ModelAttestation:
    """Select the sole model attestation advertised by a provider signature."""

    _require_provider_signature(signature)
    return find_model_attestation_for_signer(attestations, signature.signer)


async def fetch_gateway_attestation(
    api_key: str,
    *,
    signing_algo: SigningAlgo | None = None,
    policy: GatewayAttestationPolicy | None = None,
    base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
) -> FetchedGatewayAttestation:
    """Fetch Gateway evidence using the requested TLS-binding policy."""

    resolved_policy = GatewayAttestationPolicy() if policy is None else policy
    nonce = generate_nonce()
    query = {
        'nonce': nonce,
        'include_tls_fingerprint': str(resolved_policy.verify_tls_binding).lower(),
    }
    if signing_algo is not None:
        query['signing_algo'] = signing_algo
    response = await _get_cloud_api_json(
        api_key,
        _endpoint(
            base_url,
            'attestation/report',
            query,
        ),
        'gateway_attestation',
        capture_peer_spki=resolved_policy.verify_tls_binding,
    )
    attestation = _decode_gateway_attestation_report(response.json)
    if resolved_policy.verify_tls_binding and attestation.tls_spki_fingerprint is None:
        raise api_failure(
            'api.invalid_response',
            {
                'path': 'gateway_attestation.tls_cert_fingerprint',
                'expected': '32-byte hexadecimal string',
                'actual': 'missing',
            },
        )
    _require_matching_api_nonce(attestation.nonce, nonce, 'gateway_attestation')
    return FetchedGatewayAttestation(
        attestation=attestation,
        client_binding=GatewayClientBinding(
            nonce=nonce,
            peer_spki_fingerprint=response.peer_spki_fingerprint,
        ),
        policy=resolved_policy,
    )


async def lookup_completion_signature(
    api_key: str,
    completion_id: str,
    *,
    signing_algo: SigningAlgo | None = None,
    base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
) -> CompletionSignatureLookup:
    """Look up one signature without treating a 2xx unavailable envelope as an error."""

    query: dict[str, str] = {}
    if signing_algo is not None:
        query['signing_algo'] = signing_algo
    response = await _get_cloud_api_json(
        api_key,
        _endpoint(
            base_url,
            f'signature/{quote(completion_id, safe="")}',
            query,
        ),
        'completion_signature',
    )
    return _decode_completion_signature_lookup(response.json)


async def fetch_completion_signature(
    api_key: str,
    completion_id: str,
    *,
    signing_algo: SigningAlgo | None = None,
    base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
) -> CompletionSignature:
    """Fetch one completion signature or raise an ``ApiError`` if unavailable."""

    lookup = await lookup_completion_signature(
        api_key,
        completion_id,
        signing_algo=signing_algo,
        base_url=base_url,
    )
    if lookup.status == 'found' and lookup.signature is not None:
        return lookup.signature
    assert lookup.unavailable is not None
    raise api_failure(
        'api.completion_signature_unavailable',
        {'providerErrorCode': lookup.unavailable.error_code},
    )


async def _get_cloud_api_json(
    api_key: str,
    url: str,
    resource: str,
    *,
    capture_peer_spki: bool = False,
    extra_headers: Mapping[str, str] | None = None,
) -> _CloudApiJsonResponse:
    headers = {'authorization': f'Bearer {api_key}'}
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


def _decode_model_attestation_report(value: object) -> tuple[ModelAttestation, ...]:
    try:
        report = CloudModelAttestationResponseSchema.model_validate(value)
    except ValidationError as error:
        _raise_invalid_wire_response(
            error,
            root='model attestation report',
            nested_record_field='model_attestations',
        )
    if len(report.model_attestations) != 1:
        raise api_failure(
            'api.unexpected_model_attestation_count',
            {'actualCount': len(report.model_attestations)},
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
        tls_spki_fingerprint=raw.tls_cert_fingerprint,
        reported_quote_data=raw.report_data,
    )


def _decode_completion_signature_lookup(value: object) -> CompletionSignatureLookup:
    if isinstance(value, dict) and not (SIGNATURE_RESPONSE_FIELDS & set(value)):
        try:
            unavailable = CloudUnavailableSignatureSchema.model_validate(value)
        except ValidationError as error:
            _raise_invalid_wire_response(error, root='signature')
        return CompletionSignatureLookup(
            status='unavailable',
            unavailable=SignatureUnavailable(
                error_code=unavailable.error_code, message=unavailable.message
            ),
        )
    try:
        raw = CloudCompletionSignatureSchema.model_validate(value)
    except ValidationError as error:
        _raise_invalid_wire_response(error, root='signature')
    return CompletionSignatureLookup(
        status='found',
        signature=CompletionSignature(
            kind=raw.signature_kind,
            signed_text=raw.text,
            signature=raw.signature,
            signer=_api_signer(raw.signing_algo, raw.signing_address, 'signature'),
        ),
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


def find_model_attestation_for_signer(
    attestations: tuple[ModelAttestation, ...] | list[ModelAttestation],
    signer: SigningIdentity,
) -> ModelAttestation:
    matches: list[ModelAttestation] = []
    for attestation in attestations:
        if attestation.signer.signing_algo == signer.signing_algo and hex_to_bytes(
            attestation.signer.signing_address,
            'attestation.signer.signing_address',
        ) == hex_to_bytes(
            signer.signing_address,
            'signature.signer.signing_address',
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
        raise verification_failure(
            'signature.kind_mismatch',
            {'expected': 'provider_tee', 'actual': signature.kind},
        )


def _endpoint(base_url: str, path: str, query: Mapping[str, str]) -> str:
    parsed = urlsplit(base_url)
    normalized_path = f'{parsed.path.rstrip("/")}/{path}'
    return urlunsplit(
        (parsed.scheme, parsed.netloc, normalized_path, urlencode(query), '')
    )


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


def _describe_value(value: object) -> str:
    if value is None:
        return 'null'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, dict):
        return 'object'
    return type(value).__name__
