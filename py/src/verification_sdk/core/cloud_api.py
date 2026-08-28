"""NEAR AI Cloud evidence and completion-signature request helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from inspect import isawaitable
from typing import TypeVar
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ValidationError

from ..schemas import (
    CloudCompletionSignatureSchema,
    CloudGatewayAttestationResponseSchema,
    CloudGatewayAttestationSchema,
    CloudInfoSchema,
    CloudModelAttestationResponseSchema,
    CloudModelAttestationSchema,
    CloudTcbInfoSchema,
    CloudUnavailableSignatureSchema,
)
from ..types.attestation_common import SigningIdentity
from ..types.attestation_gateway import GatewayAttestation
from ..types.attestation_model import ModelAttestation
from ..types.chat import (
    CompletionSignature,
    CompletionSignatureLookup,
    CompletionSignatureReference,
    SignatureUnavailable,
)
from ..types.cloud_api import (
    NO_ALIASING_HEADER,
    FetchCompletionSignatureInput,
    FetchGatewayAttestationInput,
    FetchModelAttestationForSignatureInput,
    FetchModelAttestationsInput,
    FetchedGatewayAttestation,
    FetchedModelAttestation,
    FetchedModelAttestations,
    FindModelAttestationForSignatureInput,
    NearAiCloudOptions,
    NearAiCloudResponse,
)
from ..utils.common import generate_nonce, normalize_hex, require_instance
from ..utils.consts import TIMEOUT
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
    verification_failure,
)
from ..utils.fetch import fetch


SchemaType = TypeVar('SchemaType', bound=BaseModel)
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
    cloud: NearAiCloudOptions,
    input: FetchModelAttestationsInput,
) -> FetchedModelAttestations:
    """Fetch the current NEAR model evidence with a fresh client nonce."""

    input = require_instance(input, FetchModelAttestationsInput, 'input')
    options = _parse_cloud_options(cloud)
    _require_non_empty(input.model, 'model')
    _validate_optional_signer(
        input.signing_algo, input.signing_address, 'signing_address'
    )
    nonce = generate_nonce()
    query: dict[str, str] = {
        'model': input.model,
        'provider': 'near',
        'nonce': nonce,
    }
    if input.signing_algo is not None:
        query['signing_algo'] = input.signing_algo
    if input.signing_address is not None:
        query['signing_address'] = input.signing_address
    response = await _get_cloud_api_json(
        options,
        _endpoint(options.base_url, 'attestation/report', query),
        'model_attestation',
        {NO_ALIASING_HEADER: 'true'},
    )
    report = _parse_api_model(
        CloudModelAttestationResponseSchema, response.json, 'model attestation report'
    )
    if len(report.model_attestations) != 1:
        raise api_failure(
            'api.unexpected_model_attestation_count',
            {'expectedCount': 1, 'actualCount': len(report.model_attestations)},
        )
    attestations = tuple(
        _parse_model_attestation(value, f'model_attestations[{index}]')
        for index, value in enumerate(report.model_attestations)
    )
    for attestation in attestations:
        _require_matching_api_nonce(attestation.nonce, nonce, 'model_attestation')
    return FetchedModelAttestations(attestations=attestations, nonce=nonce)


async def fetch_model_attestation_for_signature(
    cloud: NearAiCloudOptions,
    input: FetchModelAttestationForSignatureInput,
) -> FetchedModelAttestation:
    """Fetch and select evidence for a ``provider_tee`` completion signature."""

    input = require_instance(input, FetchModelAttestationForSignatureInput, 'input')
    _require_provider_signature(input.signature)
    fetched = await fetch_model_attestations(
        cloud,
        FetchModelAttestationsInput(
            model=input.model,
            signing_algo=input.signature.signer.signing_algo,
            signing_address=input.signature.signer.signing_address,
        ),
    )
    return FetchedModelAttestation(
        attestation=_select_model_attestation_for_signer(
            fetched.attestations, input.signature.signer
        ),
        nonce=fetched.nonce,
    )


def find_model_attestation_for_signature(
    input: FindModelAttestationForSignatureInput,
) -> ModelAttestation:
    """Select the sole model attestation advertised by a provider signature."""

    input = require_instance(input, FindModelAttestationForSignatureInput, 'input')
    _require_provider_signature(input.signature)
    return _select_model_attestation_for_signer(
        input.attestations, input.signature.signer
    )


async def fetch_gateway_attestation(
    cloud: NearAiCloudOptions,
    input: FetchGatewayAttestationInput | None = None,
) -> FetchedGatewayAttestation:
    """Fetch standalone Gateway evidence in its TLS-aware report-data layout."""

    options = _parse_cloud_options(cloud)
    request = (
        FetchGatewayAttestationInput()
        if input is None
        else require_instance(input, FetchGatewayAttestationInput, 'input')
    )
    _validate_signing_algo(request.signing_algo, 'signing_algo')
    nonce = generate_nonce()
    response = await _get_cloud_api_json(
        options,
        _endpoint(
            options.base_url,
            'attestation/report',
            {
                'nonce': nonce,
                'signing_algo': request.signing_algo,
                'include_tls_fingerprint': 'true',
            },
        ),
        'gateway_attestation',
    )
    report = _parse_api_model(
        CloudGatewayAttestationResponseSchema,
        response.json,
        'gateway attestation report',
    )
    attestation = _parse_gateway_attestation(
        report.gateway_attestation, 'gateway_attestation'
    )
    _require_matching_api_nonce(attestation.nonce, nonce, 'gateway_attestation')
    return FetchedGatewayAttestation(
        attestation=attestation,
        nonce=nonce,
        peer_spki_fingerprint=_normalize_transport_peer_spki_fingerprint(
            response.peer_spki_fingerprint
        ),
    )


async def lookup_completion_signature(
    cloud: NearAiCloudOptions,
    input: FetchCompletionSignatureInput,
) -> CompletionSignatureLookup:
    """Look up one signature without treating a 2xx unavailable envelope as an error."""

    input = require_instance(input, FetchCompletionSignatureInput, 'input')
    options = _parse_cloud_options(cloud)
    _require_non_empty(input.completion_id, 'completion_id')
    if input.signing_algo is not None:
        _validate_signing_algo(input.signing_algo, 'signing_algo')
    query: dict[str, str] = {}
    if input.signing_algo is not None:
        query['signing_algo'] = input.signing_algo
    response = await _get_cloud_api_json(
        options,
        _endpoint(
            options.base_url,
            f'signature/{quote(input.completion_id, safe="")}',
            query,
        ),
        'completion_signature',
    )
    return _parse_completion_signature_lookup(response.json)


async def fetch_completion_signature(
    cloud: NearAiCloudOptions,
    input: FetchCompletionSignatureInput,
) -> CompletionSignature:
    """Fetch one completion signature or raise ``signature.unavailable``."""

    lookup = await lookup_completion_signature(cloud, input)
    if lookup.status == 'found' and lookup.signature is not None:
        return lookup.signature
    assert lookup.unavailable is not None
    raise verification_failure(
        'signature',
        'signature.unavailable',
        {'providerErrorCode': lookup.unavailable.error_code},
    )


async def _get_cloud_api_json(
    cloud: NearAiCloudOptions,
    url: str,
    resource: str,
    extra_headers: Mapping[str, str] | None = None,
) -> _CloudApiJsonResponse:
    headers = {'authorization': f'Bearer {cloud.api_key}'}
    if extra_headers is not None:
        headers.update(extra_headers)
    try:
        response = await _cloud_fetch(cloud, url, headers)
    except (ApiError, VerificationError):
        raise
    except Exception as error:
        raise api_failure(
            'api.transport_failed',
            {'resource': resource, 'reason': 'request'},
            retryable=True,
            cause=error,
        ) from error
    if not isinstance(response, NearAiCloudResponse):
        raise api_failure(
            'api.invalid_response',
            {
                'path': f'{resource} response',
                'expected': 'NearAiCloudResponse',
                'actual': type(response).__name__,
            },
        )
    if not isinstance(response.status, int) or isinstance(response.status, bool):
        raise api_failure(
            'api.invalid_response',
            {
                'path': f'{resource} response.status',
                'expected': 'integer',
                'actual': type(response.status).__name__,
            },
        )
    if not isinstance(response.body, str):
        raise api_failure(
            'api.invalid_response',
            {
                'path': f'{resource} response.body',
                'expected': 'string',
                'actual': type(response.body).__name__,
            },
        )
    if not response.ok:
        raise api_failure(
            'api.http_status',
            {'resource': resource, 'status': response.status},
            retryable=_is_retryable_status(response.status, resource),
        )
    try:
        json_body = json.loads(response.body)
    except json.JSONDecodeError as error:
        raise api_failure(
            'api.invalid_json', {'resource': resource}, cause=error
        ) from error
    return _CloudApiJsonResponse(
        json=json_body,
        peer_spki_fingerprint=response.peer_spki_fingerprint,
    )


async def _cloud_fetch(
    cloud: NearAiCloudOptions, url: str, headers: Mapping[str, str]
) -> NearAiCloudResponse:
    if cloud.fetch is not None:
        result = cloud.fetch(url, headers)
        if not isawaitable(result):
            raise verification_failure(
                'input',
                'input.invalid',
                {
                    'field': 'fetch',
                    'reason': 'unsupported_value',
                    'expected': 'async callable',
                },
            )
        return await result
    response = await fetch(url, headers=headers, timeout=TIMEOUT)
    return NearAiCloudResponse(status=response.status, body=response.text())


def _parse_model_attestation(value: object, label: str) -> ModelAttestation:
    raw = _parse_api_model(CloudModelAttestationSchema, value, label)
    # Cloud API may omit the optional wire copy. A supplied ``null`` is not a
    # report-data string and must not silently select the legacy layout.
    if raw.report_data is None and 'report_data' in raw.model_fields_set:
        raise _invalid_response(f'{label}.report_data', 'string', None)
    return ModelAttestation(
        nonce=_validate_api_nonce(raw.request_nonce, f'{label}.request_nonce'),
        signer=_api_signer(raw.signing_algo, raw.signing_address, label),
        intel_quote=raw.intel_quote,
        event_log=raw.event_log,
        app_compose=_parse_app_compose(raw.info, f'{label}.info.tcb_info'),
        declared_spki_fingerprint=raw.tls_cert_fingerprint,
        reported_quote_data=raw.report_data,
        nvidia_payload=raw.nvidia_payload,
    )


def _normalize_transport_peer_spki_fingerprint(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid_response(
            'gateway_transport.peer_spki_fingerprint',
            '32-byte hexadecimal SPKI fingerprint',
            value,
        )
    try:
        fingerprint = normalize_hex(value)
    except VerificationError as error:
        raise _invalid_response(
            'gateway_transport.peer_spki_fingerprint',
            '32-byte hexadecimal SPKI fingerprint',
            value,
            error,
        ) from error
    if len(fingerprint) != 64:
        raise _invalid_response(
            'gateway_transport.peer_spki_fingerprint',
            '32-byte hexadecimal SPKI fingerprint',
            value,
        )
    return fingerprint


def _parse_gateway_attestation(value: object, label: str) -> GatewayAttestation:
    raw = _parse_api_model(CloudGatewayAttestationSchema, value, label)
    return GatewayAttestation(
        nonce=_validate_api_nonce(raw.request_nonce, f'{label}.request_nonce'),
        signer=_api_signer(raw.signing_algo, raw.signing_address, label),
        intel_quote=raw.intel_quote,
        event_log=raw.event_log,
        app_compose=_parse_app_compose(raw.info, f'{label}.info.tcb_info'),
        declared_spki_fingerprint=raw.tls_cert_fingerprint,
        reported_quote_data=raw.report_data,
    )


def _parse_completion_signature_lookup(value: object) -> CompletionSignatureLookup:
    if isinstance(value, dict) and not (SIGNATURE_RESPONSE_FIELDS & set(value)):
        unavailable = _parse_api_model(
            CloudUnavailableSignatureSchema, value, 'signature'
        )
        return CompletionSignatureLookup(
            status='unavailable',
            unavailable=SignatureUnavailable(
                error_code=unavailable.error_code, message=unavailable.message
            ),
        )
    raw = _parse_api_model(CloudCompletionSignatureSchema, value, 'signature')
    return CompletionSignatureLookup(
        status='found',
        signature=CompletionSignature(
            kind=raw.signature_kind,
            signed_text=raw.text,
            signature=raw.signature,
            signer=_api_signer(raw.signing_algo, raw.signing_address, 'signature'),
        ),
    )


def _parse_app_compose(info: CloudInfoSchema, label: str) -> str:
    tcb_info: object = info.tcb_info
    if isinstance(tcb_info, str):
        try:
            tcb_info = json.loads(tcb_info)
        except json.JSONDecodeError as error:
            raise _invalid_response(label, 'JSON object', tcb_info, error) from error
    parsed = _parse_api_model(CloudTcbInfoSchema, tcb_info, label)
    return parsed.app_compose


def _parse_api_model(schema: type[SchemaType], value: object, root: str) -> SchemaType:
    try:
        return schema.model_validate(value)
    except ValidationError as error:
        issue = error.errors(include_url=False)[0]
        location = '.'.join(str(part) for part in issue['loc'])
        path = root if not location else f'{root}.{location}'
        raise _invalid_response(
            path, issue['msg'], issue.get('input'), error
        ) from error


def _api_signer(algorithm: str, address: str, label: str) -> SigningIdentity:
    _validate_api_signing_address(address, algorithm, f'{label}.signing_address')
    return SigningIdentity(signing_algo=algorithm, signing_address=address)


def _select_model_attestation_for_signer(
    attestations: tuple[ModelAttestation, ...] | list[ModelAttestation],
    signer: SigningIdentity,
) -> ModelAttestation:
    matches: list[ModelAttestation] = []
    for index, attestation in enumerate(attestations):
        if not isinstance(attestation, ModelAttestation):
            raise verification_failure(
                'input',
                'input.invalid',
                {
                    'field': f'attestations[{index}]',
                    'reason': 'unsupported_value',
                    'expected': 'ModelAttestation',
                },
            )
        _validate_input_signing_identity(
            attestation.signer, f'attestations[{index}].signer'
        )
        if attestation.signer.signing_algo == signer.signing_algo and _same_hex(
            attestation.signer.signing_address, signer.signing_address
        ):
            matches.append(attestation)
    if not matches:
        raise api_failure(
            'api.attestation_signer_mismatch', {'resource': 'model_attestation'}
        )
    if len(matches) != 1:
        raise api_failure(
            'api.ambiguous_model_attestation_signer',
            {'matchingCount': len(matches), 'totalCount': len(attestations)},
        )
    return matches[0]


def _same_hex(left: str, right: str) -> bool:
    try:
        return normalize_hex(left) == normalize_hex(right)
    except VerificationError as error:
        raise api_failure(
            'api.attestation_signer_mismatch',
            {'resource': 'model_attestation'},
            cause=error,
        ) from error


def _require_provider_signature(signature: CompletionSignatureReference) -> None:
    if not isinstance(signature, CompletionSignatureReference):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'signature',
                'reason': 'unsupported_value',
                'expected': 'CompletionSignatureReference',
            },
        )
    if signature.kind not in {'provider_tee', 'gateway'}:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'signature.kind',
                'reason': 'unsupported_value',
                'expected': "'provider_tee' or 'gateway'",
            },
        )
    if signature.kind != 'provider_tee':
        raise verification_failure(
            'signature',
            'signature.kind_mismatch',
            {'expected': 'provider_tee', 'actual': signature.kind},
        )
    _validate_input_signing_identity(signature.signer, 'signature.signer')


def _validate_input_signing_identity(signer: SigningIdentity, field: str) -> None:
    if not isinstance(signer, SigningIdentity):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': field,
                'reason': 'unsupported_value',
                'expected': 'SigningIdentity',
            },
        )
    _validate_signing_algo(signer.signing_algo, f'{field}.signing_algo')
    _validate_input_signing_address(
        signer.signing_address,
        signer.signing_algo,
        f'{field}.signing_address',
    )


def _parse_cloud_options(cloud: NearAiCloudOptions) -> NearAiCloudOptions:
    if not isinstance(cloud, NearAiCloudOptions):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'cloud',
                'reason': 'unsupported_value',
                'expected': 'NearAiCloudOptions',
            },
        )
    if not isinstance(cloud.api_key, str):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'api_key',
                'reason': 'unsupported_value',
                'expected': 'string',
            },
        )
    if not cloud.api_key:
        raise verification_failure(
            'input', 'input.invalid', {'field': 'api_key', 'reason': 'missing'}
        )
    if any(
        ord(character) <= 0x1F or ord(character) == 0x7F for character in cloud.api_key
    ):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'api_key',
                'reason': 'invalid_header',
                'expected': 'non-empty HTTP header value',
            },
        )
    if cloud.fetch is not None and not callable(cloud.fetch):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'fetch',
                'reason': 'unsupported_value',
                'expected': 'async callable',
            },
        )
    _validate_base_url(cloud.base_url)
    return cloud


def _validate_base_url(base_url: str) -> None:
    if not isinstance(base_url, str):
        raise _invalid_base_url()
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise _invalid_base_url(error) from error
    if (
        '?' in base_url
        or '#' in base_url
        or parsed.scheme != 'https'
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise _invalid_base_url()


def _invalid_base_url(cause: BaseException | None = None):
    return verification_failure(
        'input',
        'input.invalid',
        {
            'field': 'base_url',
            'reason': 'invalid_url',
            'expected': 'absolute HTTPS URL without credentials, query, or fragment',
        },
        cause=cause,
    )


def _endpoint(base_url: str, path: str, query: Mapping[str, str]) -> str:
    parsed = urlsplit(base_url)
    normalized_path = f'{parsed.path.rstrip("/")}/{path}'
    return urlunsplit(
        (parsed.scheme, parsed.netloc, normalized_path, urlencode(query), '')
    )


def _validate_optional_signer(
    algorithm: str | None, address: str | None, field: str
) -> None:
    if algorithm is not None:
        _validate_signing_algo(algorithm, 'signing_algo')
    if address is None:
        return
    if algorithm is not None:
        _validate_input_signing_address(address, algorithm, field)
        return
    normalized = _normalized_input_hex(address, field)
    if len(normalized) not in {40, 64}:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': field,
                'reason': 'wrong_length',
                'expected': '20-byte ECDSA or 32-byte Ed25519 hexadecimal signing address',
                'actualBytes': len(normalized) // 2,
            },
        )


def _validate_signing_algo(algorithm: str, field: str) -> None:
    if not isinstance(algorithm, str) or algorithm not in {'ecdsa', 'ed25519'}:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': field,
                'reason': 'unsupported_value',
                'expected': "'ecdsa' or 'ed25519'",
            },
        )


def _validate_api_signing_address(address: str, algorithm: str, label: str) -> None:
    expected_bytes = 20 if algorithm == 'ecdsa' else 32
    normalized = _normalized_api_hex(address, label)
    if len(normalized) != expected_bytes * 2:
        raise _invalid_response(
            label, f'{expected_bytes}-byte hexadecimal signing address', address
        )


def _validate_input_signing_address(address: str, algorithm: str, field: str) -> None:
    expected_bytes = 20 if algorithm == 'ecdsa' else 32
    normalized = _normalized_input_hex(address, field)
    if len(normalized) != expected_bytes * 2:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': field,
                'reason': 'wrong_length',
                'expectedBytes': expected_bytes,
                'actualBytes': len(normalized) // 2,
            },
        )


def _validate_api_nonce(value: str, label: str) -> str:
    normalized = _normalized_api_hex(value, label)
    if len(normalized) != 64:
        raise _invalid_response(label, '32-byte hexadecimal nonce', value)
    return value


def _normalized_api_hex(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise _invalid_response(label, 'hexadecimal text', value)
    normalized = value[2:] if value.startswith(('0x', '0X')) else value
    if (
        not normalized
        or len(normalized) % 2 != 0
        or any(character not in '0123456789abcdefABCDEF' for character in normalized)
    ):
        raise _invalid_response(label, 'hexadecimal text', value)
    return normalized


def _normalized_input_hex(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise verification_failure(
            'input', 'input.invalid', {'field': field, 'reason': 'invalid_hex'}
        )
    normalized = value[2:] if value.startswith(('0x', '0X')) else value
    if (
        not normalized
        or len(normalized) % 2 != 0
        or any(character not in '0123456789abcdefABCDEF' for character in normalized)
    ):
        raise verification_failure(
            'input', 'input.invalid', {'field': field, 'reason': 'invalid_hex'}
        )
    return normalized


def _require_matching_api_nonce(reported: str, requested: str, resource: str) -> None:
    if _normalized_api_hex(reported, f'{resource}.request_nonce').lower() == requested:
        return
    raise api_failure('api.nonce_mismatch', {'resource': resource})


def _is_retryable_status(status: int, resource: str) -> bool:
    return (
        (resource == 'completion_signature' and status == 404)
        or status in {408, 425, 429}
        or status >= 500
    )


def _require_non_empty(value: str, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise verification_failure(
            'input',
            'input.invalid',
            {'field': field, 'reason': 'missing', 'expected': 'non-empty string'},
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
