"""Pydantic schemas used only at untrusted HTTP and verifier boundaries."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)


class ApiSchema(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)


class CloudTcbInfoSchema(ApiSchema):
    app_compose: StrictStr


class CloudInfoSchema(ApiSchema):
    tcb_info: CloudTcbInfoSchema

    @field_validator('tcb_info', mode='before')
    @classmethod
    def decode_tcb_info(cls, value: Any) -> Any:
        """Normalize Cloud API's object-or-JSON-string TCB info field."""

        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError('expected a JSON object') from error


class CloudAttestationSchema(ApiSchema):
    request_nonce: StrictStr
    signing_algo: Literal['ecdsa', 'ed25519']
    signing_address: StrictStr
    intel_quote: StrictStr
    event_log: StrictStr | list[Any]
    info: CloudInfoSchema
    tls_cert_fingerprint: StrictStr | None = None
    report_data: StrictStr | None = None


class CloudModelAttestationSchema(CloudAttestationSchema):
    nvidia_payload: StrictStr | None = None


class CloudGatewayAttestationSchema(CloudAttestationSchema):
    tls_cert_fingerprint: StrictStr
    report_data: StrictStr


class CloudModelAttestationResponseSchema(ApiSchema):
    model_attestations: list[CloudModelAttestationSchema]


class CloudGatewayAttestationResponseSchema(ApiSchema):
    gateway_attestation: CloudGatewayAttestationSchema


class CloudCompletionSignatureSchema(ApiSchema):
    text: StrictStr
    signature: StrictStr
    signing_address: StrictStr
    signing_algo: Literal['ecdsa', 'ed25519']
    signature_kind: Literal['provider_tee', 'gateway']


class CloudUnavailableSignatureSchema(ApiSchema):
    error_code: StrictStr
    message: StrictStr


class _NrasResponseSchema(ApiSchema):
    """The portion of an NRAS response the SDK consumes."""

    overall_attestation_jwt: StrictStr

    @model_validator(mode='before')
    @classmethod
    def extract_overall_attestation_jwt(cls, value: Any) -> dict[str, Any]:
        if (
            not isinstance(value, list)
            or not value
            or not isinstance(value[0], list)
            or len(value[0]) < 2
            or value[0][0] != 'JWT'
        ):
            raise ValueError('expected the first NRAS entry to begin with JWT')
        return {'overall_attestation_jwt': value[0][1]}


class _NrasJwtPayloadSchema(RootModel[dict[str, object]]):
    """A JWT payload must decode to a JSON object."""

    model_config = ConfigDict(strict=True)


class _NrasOverallAttestationJwtClaimsSchema(ApiSchema):
    overall_attestation_result: StrictBool = Field(
        validation_alias='x-nvidia-overall-att-result'
    )
