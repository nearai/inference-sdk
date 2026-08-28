"""Pydantic schemas used only at untrusted HTTP and verifier boundaries."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, StrictStr


class ApiSchema(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)


class CloudTcbInfoSchema(ApiSchema):
    app_compose: StrictStr


class CloudInfoSchema(ApiSchema):
    tcb_info: CloudTcbInfoSchema | StrictStr


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
    report_data: StrictStr


class CloudModelAttestationResponseSchema(ApiSchema):
    model_attestations: list[Any]


class CloudGatewayAttestationResponseSchema(ApiSchema):
    gateway_attestation: Any


class CloudCompletionSignatureSchema(ApiSchema):
    text: StrictStr
    signature: StrictStr
    signing_address: StrictStr
    signing_algo: Literal['ecdsa', 'ed25519']
    signature_kind: Literal['provider_tee', 'gateway']


class CloudUnavailableSignatureSchema(ApiSchema):
    error_code: StrictStr
    message: StrictStr
