"""Pydantic schemas used only at untrusted HTTP and verifier boundaries."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


class ApiSchema(BaseModel):
    model_config = ConfigDict(extra='ignore', strict=True)


class GitHubImageAttestationSchema(ApiSchema):
    # Sigstore owns bundle parsing; do not duplicate its certificate/log schema.
    bundle: dict[str, Any]


class GitHubImageAttestationsSchema(ApiSchema):
    attestations: list[GitHubImageAttestationSchema]


class DeploymentAppComposeSchema(ApiSchema):
    docker_compose_file: StrictStr


class DeploymentComposeServiceSchema(ApiSchema):
    image: StrictStr | None = None


class DeploymentDockerComposeSchema(ApiSchema):
    services: dict[str, DeploymentComposeServiceSchema]


class SlsaSubjectSchema(ApiSchema):
    digest: dict[str, StrictStr]


class SlsaDependencySchema(ApiSchema):
    uri: StrictStr
    digest: dict[str, StrictStr] = Field(default_factory=dict)


class SlsaWorkflowSchema(ApiSchema):
    repository: StrictStr
    path: StrictStr
    ref: StrictStr


class SlsaExternalParametersSchema(ApiSchema):
    workflow: SlsaWorkflowSchema


class SlsaBuildDefinitionSchema(ApiSchema):
    external_parameters: SlsaExternalParametersSchema = Field(
        validation_alias='externalParameters'
    )
    resolved_dependencies: list[SlsaDependencySchema] = Field(
        validation_alias='resolvedDependencies'
    )


class SlsaConfigSourceSchema(ApiSchema):
    uri: StrictStr
    entry_point: StrictStr = Field(validation_alias='entryPoint')
    digest: dict[str, StrictStr]


class SlsaInvocationSchema(ApiSchema):
    config_source: SlsaConfigSourceSchema = Field(validation_alias='configSource')


class SlsaPredicateSchema(ApiSchema):
    build_definition: SlsaBuildDefinitionSchema | None = Field(
        default=None, validation_alias='buildDefinition'
    )
    invocation: SlsaInvocationSchema | None = None


class SlsaStatementSchema(ApiSchema):
    statement_type: Literal[
        'https://in-toto.io/Statement/v1', 'https://in-toto.io/Statement/v0.1'
    ] = Field(validation_alias='_type')
    subject: list[SlsaSubjectSchema]
    predicate_type: Literal[
        'https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2'
    ] = Field(validation_alias='predicateType')
    predicate: SlsaPredicateSchema


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
    tls_cert_fingerprint: StrictStr | None = None


class CloudModelAttestationSchema(CloudAttestationSchema):
    info: CloudInfoSchema
    report_data: StrictStr | None = None
    nvidia_payload: StrictStr | None = None
    signing_public_key: StrictStr | None = None


class CloudGatewayAttestationSchema(CloudAttestationSchema):
    info: CloudInfoSchema
    report_data: StrictStr


class CloudModelAttestationResponseSchema(ApiSchema):
    # Cloud API omits this field when no model provider produced evidence.
    model_attestations: list[CloudModelAttestationSchema] = Field(default_factory=list)


class ModelMetadataSchema(ApiSchema):
    provider_type: StrictStr = Field(validation_alias='providerType')
    attestation_supported: StrictBool = Field(validation_alias='attestationSupported')


class ModelMetadataResponseSchema(ApiSchema):
    metadata: ModelMetadataSchema


class OhttpAttestationSchema(ApiSchema):
    signing_algo: Literal['ed25519']
    signing_key: StrictStr
    key_config: StrictStr
    signature: StrictStr


class CloudGatewayAttestationResponseSchema(ApiSchema):
    gateway_attestation: CloudGatewayAttestationSchema
    ohttp_attestation: OhttpAttestationSchema | None = None


class CompletionSignatureFieldsSchema(ApiSchema):
    text: StrictStr
    signature: StrictStr
    signing_address: StrictStr
    signing_algo: Literal['ecdsa', 'ed25519']


class CloudCompletionSignatureSchema(CompletionSignatureFieldsSchema):
    signature_kind: Literal['provider_tee', 'gateway']


class DirectInfoSchema(CloudInfoSchema):
    instance_id: StrictStr | None = None


class DirectModelAttestationSchema(CloudAttestationSchema):
    model_name: StrictStr = Field(min_length=1)
    info: DirectInfoSchema
    report_data: StrictStr | None = None
    nvidia_payload: StrictStr | None = None
    signing_public_key: StrictStr | None = None


class DirectAttestationReportSchema(DirectModelAttestationSchema):
    all_attestations: list[DirectModelAttestationSchema] = Field(min_length=1)
    ohttp_attestation: OhttpAttestationSchema | None = None


class DirectCompletionSignatureSchema(CompletionSignatureFieldsSchema):
    # The direct endpoint itself establishes the signature's trust boundary.
    signature_kind: Literal['provider_tee'] = 'provider_tee'


class CloudUnavailableSignatureSchema(ApiSchema):
    error_code: StrictStr
    message: StrictStr


class CompletionRequestModelSchema(ApiSchema):
    """The model identifier embedded in signed completion request bytes."""

    model: StrictStr = Field(min_length=1)

    @field_validator('model')
    @classmethod
    def reject_dot_segments(cls, value: str) -> str:
        if value in ('.', '..'):
            raise ValueError('Model ID cannot be a dot path segment')
        return value


class ChatCompletionRequestSchema(CompletionRequestModelSchema):
    """Only identify the model; leave Chat field validation to the server."""

    model_config = ConfigDict(extra='allow', strict=True)


class ChatCompletionResponseSchema(RootModel[dict[str, Any]]):
    model_config = ConfigDict(strict=True)


class CompletionResponseIdSchema(ApiSchema):
    id: StrictStr = Field(min_length=1)


SystemOneContent = str | dict[str, Any] | list[Any]
SystemOneProbability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class SystemOneNoulAnswerSchema(ApiSchema):
    model_config = ConfigDict(extra='allow', strict=True)
    type: Literal['noul']
    noul: SystemOneProbability


class SystemOneChoiceAnswerSchema(ApiSchema):
    model_config = ConfigDict(extra='allow', strict=True)
    type: Literal['choice']
    choice: StrictStr
    confidence: SystemOneProbability
    probabilities: dict[str, SystemOneProbability]


class SystemOneScoreAnswerSchema(ApiSchema):
    model_config = ConfigDict(extra='allow', strict=True)
    type: Literal['score']
    score: float = Field(allow_inf_nan=False)
    confidence: SystemOneProbability
    probabilities: dict[str, SystemOneProbability]
    legend: dict[str, SystemOneContent]


class SystemOneUsageSchema(ApiSchema):
    model_config = ConfigDict(extra='allow', strict=True)
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)


class SystemOneResponseSchema(ApiSchema):
    model_config = ConfigDict(extra='allow', strict=True)
    id: StrictStr | None = None
    model: StrictStr = Field(min_length=1)
    answers: dict[
        str,
        Annotated[
            SystemOneNoulAnswerSchema
            | SystemOneChoiceAnswerSchema
            | SystemOneScoreAnswerSchema,
            Field(discriminator='type'),
        ],
    ]
    usage: SystemOneUsageSchema


class NvidiaPayloadNonceSchema(ApiSchema):
    """The nonce echoed by NVIDIA GPU evidence."""

    nonce: StrictStr


class DstackEventLogEntrySchema(ApiSchema):
    """One dstack event-log record used while replaying RTMR3."""

    digest: StrictStr
    imr: StrictInt = Field(ge=0, le=0xFFFFFFFF)
    event_type: StrictInt = Field(default=0, ge=0, le=0xFFFFFFFF)
    event: StrictStr = ''
    event_payload: StrictStr = ''


class DstackEventLogSchema(RootModel[list[DstackEventLogEntrySchema]]):
    """A parsed dstack event log."""

    model_config = ConfigDict(strict=True)


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


class _NrasOverallAttestationJwtClaimsSchema(ApiSchema):
    overall_attestation_result: StrictBool = Field(
        validation_alias='x-nvidia-overall-att-result'
    )
    eat_nonce: StrictStr = Field(pattern=r'^[0-9a-fA-F]{64}$')
    exp: StrictInt
    nbf: StrictInt
    iat: StrictInt


class _NvidiaJwksSchema(ApiSchema):
    keys: list[dict[str, object]]
