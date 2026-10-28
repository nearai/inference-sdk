"""Verified Chat Completions and an HTTP client usable by AsyncOpenAI."""

from __future__ import annotations

import asyncio
import codecs
import json
import math
import re
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, replace
from time import monotonic, time
from typing import TYPE_CHECKING, Self

import httpx
from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
from pydantic import ValidationError

from ..schemas import CompletionResponseIdSchema
from ..types.attestation_common import SigningAlgo
from ..types.chat import CompletionSignature
from ..types.cloud_api import (
    DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    NO_ALIASING_HEADER,
    FetchedGatewayAttestation,
)
from ..types.e2ee import E2eeModelKey
from ..types.inference_client import (
    AttestationVerificationResult,
    DeploymentPolicy,
    GatewayVerificationOptions,
    ModelVerificationOptions,
    VerifiedCompletionResult,
    VerifiedGatewayCompletionResult,
    VerifiedModelCompletionResult,
)
from ..types.verification import (
    MeasuredDeployment,
    ModelAttestationVerifiers,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
)
from ..utils.common import gather_cancel_on_error, maybe_await
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
    verification_failure,
)
from ..utils.fetch import FetchResponse
from ..utils.sse import get_sse_data_records, get_sse_event, take_complete_sse_records
from .attestation_gateway import verify_gateway_attestation
from .attestation_model import verify_model_attestation
from .chat import verify_gateway_response, verify_model_response
from .cloud_api import (
    AttestationClient,
    _ApiClient,
    _validate_base_url,
)
from .e2ee_request import (
    decode_chat_request,
    prepare_e2ee_chat_request,
    remove_e2ee_headers,
)
from .ohttp import create_ohttp_client
from .ohttp_attestation import verify_ohttp_key_config
from .pinned_tls import create_pinned_tls_client
from .systemone import InferenceSystemOne

if TYPE_CHECKING:
    import httpx2

DEFAULT_CACHE_TIME_TO_LIVE_MS = 60 * 60 * 1000
_OPENAI_PLACEHOLDER = 'nearai-inference-sdk-internal'


@dataclass(frozen=True)
class _VerifiedSession[Result, AttestationResult]:
    model_key: E2eeModelKey | None
    http_client: httpx.AsyncClient
    attestation_client: _ApiClient
    verify_response: Callable[[str, bytes, bytes, CompletionSignature], Result]
    attestation_result: AttestationResult


@dataclass
class _ResponseRecord[Result, AttestationResult]:
    request_body: bytes
    response_body: asyncio.Future[bytes]
    session: _VerifiedSession[Result, AttestationResult]
    gateway_only: bool = False
    verification: asyncio.Task[Result] | None = None
    expiry: asyncio.TimerHandle | None = None
    expires_at: float | None = None


class _SessionAttestationClient(AttestationClient):
    """Keep model evidence and response signatures on the pinned transport."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        api_key: str | None,
        base_url: str,
        headers: Mapping[str, str],
    ) -> None:
        super().__init__(api_key, base_url=base_url, headers=headers)
        self._http_client = http_client

    async def _fetch(
        self, url: str, *, headers: Mapping[str, str], _capture_peer_spki: bool = False
    ) -> FetchResponse:
        response = await self._http_client.get(url, headers=headers)
        return FetchResponse(
            status=response.status_code,
            body=response.content,
            headers=response.headers,
        )


class _InferenceTransport(httpx.AsyncBaseTransport):
    def __init__(
        self, client: _VerifiedInferenceClient, *, anthropic: bool = False
    ) -> None:
        self._client = client
        self._anthropic = anthropic

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._anthropic:
            base = httpx.URL(self._client.base_url)
            if request.url.copy_with(query=None) == base.join('v1/messages'):
                request.url = base.join('messages').copy_with(
                    query=request.url.query or None
                )
        return await self._client.send(request)


class _VerifiedInferenceClient[Result, AttestationResult]:
    """Verify before sending Chat requests, then verify responses explicitly.

    ``chat.completions.create`` is the standard asynchronous OpenAI interface.
    Pass ``http_client`` to an external ``AsyncOpenAI`` to use the same verified
    transport. Both paths retain encrypted wire bytes for ``verify_response``.
    Use ``async with`` or call ``aclose`` to release connections and caches.
    """

    _supports_gateway_endpoints = False

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
        headers: Mapping[str, str] | None = None,
        e2ee: bool = False,
        ohttp: bool = False,
        signing_algo: SigningAlgo = 'ed25519',
        attestation_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        response_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        model_verification: ModelVerificationOptions | None = None,
        deployment_policy: DeploymentPolicy | None = None,
    ) -> None:
        for field, value in (
            ('attestation_cache_time_to_live_ms', attestation_cache_time_to_live_ms),
            ('response_cache_time_to_live_ms', response_cache_time_to_live_ms),
        ):
            if not math.isfinite(value) or value < 0:
                raise api_failure(
                    'api.invalid_input',
                    {
                        'field': field,
                        'reason': 'unsupported_value',
                        'expected': 'a finite non-negative duration in milliseconds',
                    },
                )
        if ohttp and signing_algo != 'ed25519':
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'signing_algo',
                    'reason': 'unsupported_value',
                    'expected': 'ed25519 when OHTTP is enabled',
                    'actual': signing_algo,
                },
            )
        self.base_url = _validate_base_url(base_url).rstrip('/') + '/'
        self._api_key = api_key
        self._headers = httpx.Headers(headers)
        if api_key is not None:
            self._headers['authorization'] = f'Bearer {api_key}'
            self._headers.pop('api-key', None)
        self._signing_algo: SigningAlgo = signing_algo
        self._e2ee = e2ee
        self._ohttp = ohttp
        self._attestation_ttl = attestation_cache_time_to_live_ms / 1000
        self._response_ttl = response_cache_time_to_live_ms / 1000
        self._model_options = model_verification or ModelVerificationOptions()
        self._deployment_policy = deployment_policy
        self._sessions: dict[
            str,
            tuple[float, _VerifiedSession[Result, AttestationResult]],
        ] = {}
        self._pending: dict[
            str,
            asyncio.Task[_VerifiedSession[Result, AttestationResult]],
        ] = {}
        self._http_clients: dict[str | tuple[str, ...] | None, httpx.AsyncClient] = {}
        self._responses: dict[str, _ResponseRecord[Result, AttestationResult]] = {}
        self._drains: set[asyncio.Task[None]] = set()
        self._chat_client = httpx.AsyncClient(
            transport=_InferenceTransport(self), timeout=None
        )
        # The wrapper requires a key even when an aggregator uses custom
        # authentication. send() replaces its headers with this configuration.
        self._openai = AsyncOpenAI(
            api_key=api_key or _OPENAI_PLACEHOLDER,
            base_url=self.base_url,
            http_client=self._chat_client,
            max_retries=0,
        )
        self.chat = self._openai.chat

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Return a non-owning HTTPX adapter for an external SDK.

        Each adapter may be closed independently; the inference client owns
        the connections, sessions, and response-verification records.
        """
        return httpx.AsyncClient(transport=_InferenceTransport(self), timeout=None)

    @property
    def httpx2_client(self) -> httpx2.AsyncClient:
        """Return a non-owning HTTPX2 adapter using the same request pipeline.

        Install ``httpx2`` before accessing this property; it is loaded on demand.
        The adapter shares this client's supported endpoints, verification,
        encryption, and receipts. Each access returns a new adapter that may be
        closed independently. Keep the owner open while sending and verifying.
        """
        from ..integrations.httpx2 import _create_httpx2_client

        return _create_httpx2_client(self)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._chat_client.aclose()
        await self._close_sessions()

    async def _close_sessions(self) -> None:
        pending = [*self._pending.values(), *self._drains]
        pending.extend(
            record.verification
            for record in self._responses.values()
            if record.verification is not None
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for record in self._responses.values():
            if record.expiry is not None:
                record.expiry.cancel()
        await asyncio.gather(
            *(client.aclose() for client in self._http_clients.values())
        )
        self._http_clients.clear()
        self._sessions.clear()
        self._responses.clear()

    async def verify(self, model: str) -> AttestationResult:
        """Return verified deployment evidence without sending Chat.

        Shares Chat's attestation cache and in-flight work. Cache hits retain
        the original result and verified_at time. A later Chat verifies again
        when the cache expires or its time to live is zero.
        """

        if model == '':
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'model',
                    'reason': 'missing_model',
                    'expected': 'a non-empty model ID',
                },
            )
        session = await self._start_verification(model)
        return session.attestation_result

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Send a Chat or Gateway Responses request; read or stream the body.

        This is the low-level counterpart of ``http_client.send``. Consume or
        close its response, and finish a stream before calling verify_response.
        """

        expected = httpx.URL(self.base_url).join('chat/completions')
        actual = request.url.copy_with(query=None)
        responses = actual == httpx.URL(self.base_url).join('responses')
        messages = actual == httpx.URL(self.base_url).join('messages')
        if request.method != 'POST' or (
            actual != expected
            and not ((responses or messages) and self._supports_gateway_endpoints)
        ):
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'request',
                    'reason': 'unsupported_value',
                    'expected': 'a POST to a supported inference creation endpoint',
                },
            )
        if (responses or messages) and self._e2ee:
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'e2ee',
                    'reason': 'unsupported_value',
                    'expected': 'field-level E2EE disabled for Responses and Messages',
                },
            )
        parsed = await decode_chat_request(request)
        body = request.content
        headers = self._request_headers(request.headers)
        if messages:
            headers.pop('x-api-key', None)
            if 'x-api-key' in self._headers:
                headers['x-api-key'] = self._headers['x-api-key']
            headers.setdefault('anthropic-version', '2023-06-01')
        session = await self._start_verification(parsed['model'])
        # The async request body has been buffered; HTTPX sets Content-Length.
        headers.pop('transfer-encoding', None)
        headers.pop('trailer', None)
        prepared_request = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=body,
            extensions=request.extensions,
        )
        prepared = None
        if self._e2ee:
            if session.model_key is None:
                raise verification_failure('policy.model_attestation_required')
            prepared = await prepare_e2ee_chat_request(
                prepared_request, session.model_key
            )
            prepared_request = prepared.request
        else:
            remove_e2ee_headers(prepared_request.headers)
            prepared_request.headers[NO_ALIASING_HEADER] = 'true'
            if session.model_key is not None and not messages:
                prepared_request.headers['x-model-pub-key'] = (
                    session.model_key.public_key
                )
        try:
            response = await session.http_client.send(prepared_request, stream=True)
        except (ApiError, VerificationError):
            raise
        except httpx.HTTPError as error:
            raise api_failure(
                'api.transport_failed',
                {'resource': 'completion', 'reason': 'request'},
                retryable=True,
                cause=error,
            ) from error
        if not response.is_success:
            return response
        response_body = asyncio.get_running_loop().create_future()
        response_body.add_done_callback(_observe_exception)
        request_body = await prepared_request.aread()

        def register(completion_id: str) -> None:
            self._register_response(
                completion_id,
                request_body,
                response_body,
                session,
                gateway_only=responses or messages,
            )

        captured = httpx.Response(
            response.status_code,
            headers=_decoded_headers(response.headers),
            stream=_CapturedResponseStream(
                response,
                response_body,
                register,
                self,
                responses=responses,
                messages=messages,
            ),
            extensions=response.extensions,
            request=prepared_request,
        )
        if prepared is not None:
            return await prepared.decrypt_response(captured)
        return captured

    def _request_headers(self, request_headers: Mapping[str, str]) -> httpx.Headers:
        headers = httpx.Headers(self._headers)
        try:
            headers.update(request_headers)
        except UnicodeError:
            raise api_failure(
                'api.invalid_input',
                {'field': 'headers', 'reason': 'invalid_header_value'},
            ) from None
        # Use the same configured authorization for Chat and signatures,
        # including when an external OpenAI client supplies its own API key.
        if 'authorization' in self._headers:
            headers['authorization'] = self._headers['authorization']
        else:
            headers.pop('authorization', None)
        if self._api_key is not None:
            headers.pop('api-key', None)
        # HTTPX stores headers without checking the syntax sent on the wire.
        for name, value in headers.raw:
            if (
                not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or re.search(rb'[\x00-\x08\x0a-\x1f\x7f]', value)
                or value != value.strip(b' \t')
            ):
                raise api_failure(
                    'api.invalid_input',
                    {'field': 'headers', 'reason': 'invalid_header_value'},
                )
        return headers

    async def verify_response(self, id: str) -> Result:
        """Verify a retained response against the evidence used before sending."""

        record = self._get_response_record(id)
        if record is None:
            raise api_failure('api.completion_not_found')
        if record.verification is None:
            record.verification = asyncio.create_task(self._verify_record(id, record))
            record.verification.add_done_callback(_observe_exception)
        return await asyncio.shield(record.verification)

    def _get_response_record(
        self, id: str
    ) -> _ResponseRecord[Result, AttestationResult] | None:
        record = self._responses.get(id)
        if (
            record is not None
            and record.expires_at is not None
            and record.expires_at <= monotonic()
        ):
            del self._responses[id]
            if record.expiry is not None:
                record.expiry.cancel()
            return None
        return record

    async def _verify_record(
        self, id: str, record: _ResponseRecord[Result, AttestationResult]
    ) -> Result:
        try:
            body = await record.response_body
            signature = (
                await record.session.attestation_client.fetch_completion_signature(
                    id, signing_algo=self._signing_algo
                )
            )
            if signature.signer.signing_algo != self._signing_algo:
                raise verification_failure('signature.signer_mismatch')
            if record.gateway_only and signature.kind != 'gateway':
                raise verification_failure(
                    'signature.kind_mismatch',
                    {'expected': 'gateway', 'actual': signature.kind},
                )
            return record.session.verify_response(
                id, record.request_body, body, signature
            )
        except ApiError as error:
            # Reset shared retry state even when every waiter has been cancelled.
            if (
                error.retryable
                or error.failure.code == 'api.completion_signature_unavailable'
            ):
                record.verification = None
            raise

    async def _start_verification(
        self, model: str
    ) -> _VerifiedSession[Result, AttestationResult]:
        if self._chat_client.is_closed:
            raise RuntimeError('InferenceClient is closed')
        cache_key = model
        now = monotonic()
        self._sessions = {
            name: value for name, value in self._sessions.items() if value[0] > now
        }
        if self._attestation_ttl != 0 and cache_key in self._sessions:
            return self._sessions[cache_key][1]
        task = self._pending.get(cache_key)
        if task is None:
            task = asyncio.create_task(self._create_session(model))
            self._pending[cache_key] = task

            def finished(
                completed: asyncio.Task[_VerifiedSession[Result, AttestationResult]],
            ) -> None:
                self._pending.pop(cache_key, None)
                if (
                    not completed.cancelled()
                    and completed.exception() is None
                    and self._attestation_ttl != 0
                ):
                    self._sessions[cache_key] = (
                        monotonic() + self._attestation_ttl,
                        completed.result(),
                    )

            task.add_done_callback(finished)
        # Cancelling one caller must not cancel shared verification for others.
        return await asyncio.shield(task)

    async def _create_session(
        self, model: str
    ) -> _VerifiedSession[Result, AttestationResult]:
        raise NotImplementedError

    def _get_model_verifiers(self, model: str) -> ModelAttestationVerifiers | None:
        verifiers = self._model_options.verifiers
        check_deployment = self._deployment_policy
        if check_deployment is None:
            return verifiers
        original = None if verifiers is None else verifiers.deployment

        async def deployment_policy(deployment: MeasuredDeployment) -> None:
            if original is not None:
                await maybe_await(original(deployment))
            await maybe_await(check_deployment(model, deployment))

        return replace(
            verifiers or ModelAttestationVerifiers(), deployment=deployment_policy
        )

    def _completion_client(
        self, client: httpx.AsyncClient, key_config: bytes | None
    ) -> httpx.AsyncClient:
        if key_config is None:
            return client
        # The wrapper borrows this client's connections. Its session/response
        # records retain it only while needed; no separate owner registry is needed.
        return create_ohttp_client(
            key_config,
            base_url=self.base_url,
            http_client=client,
            forwarded_headers=tuple(self._headers),
        )

    def _register_response(
        self,
        id: str,
        request_body: bytes,
        response_body: asyncio.Future[bytes],
        session: _VerifiedSession[Result, AttestationResult],
        *,
        gateway_only: bool = False,
    ) -> None:
        """Retain exact wire bytes for expiry and independent verification retries."""

        if self._chat_client.is_closed:
            raise RuntimeError('InferenceClient is closed')
        if self._response_ttl == 0:
            return
        if self._get_response_record(id) is not None:
            raise api_failure('api.duplicate_completion_id')
        record = _ResponseRecord(
            request_body, response_body, session, gateway_only=gateway_only
        )
        self._responses[id] = record

        def settled(_future: asyncio.Future[bytes]) -> None:
            # A completed future's callback may run after close or replacement.
            if self._chat_client.is_closed or self._responses.get(id) is not record:
                return

            def expire() -> None:
                if self._responses.get(id) is record:
                    del self._responses[id]

            record.expires_at = monotonic() + self._response_ttl
            record.expiry = asyncio.get_running_loop().call_later(
                self._response_ttl, expire
            )

        record.response_body.add_done_callback(settled)


class InferenceClient(
    _VerifiedInferenceClient[VerifiedCompletionResult, AttestationVerificationResult]
):
    """Gateway Chat and System One with preflight and explicit response verification.

    E2EE is opt-in. NEAR TEE models require model evidence; Incognito models
    verify only the Gateway. All calls share the configured authentication.
    """

    _supports_gateway_endpoints = True

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
        headers: Mapping[str, str] | None = None,
        e2ee: bool = False,
        ohttp: bool = False,
        signing_algo: SigningAlgo = 'ed25519',
        attestation_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        response_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        gateway_verification: GatewayVerificationOptions | None = None,
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
        self._gateway_options = gateway_verification or GatewayVerificationOptions()
        self.responses = self._openai.responses
        self._anthropic = AsyncAnthropic(
            api_key='@nearai/inference-sdk-internal',
            base_url=self.base_url,
            default_headers={
                'anthropic-version': self._headers.get(
                    'anthropic-version', '2023-06-01'
                ),
            },
            max_retries=0,
            http_client=httpx.AsyncClient(
                transport=_InferenceTransport(self, anthropic=True), timeout=None
            ),
        )
        self.messages = self._anthropic.messages
        self._attestation_client = AttestationClient(
            api_key, base_url=self.base_url, headers=self._headers
        )
        self.systemone = InferenceSystemOne(self)

    async def aclose(self) -> None:
        await self._anthropic.close()
        await super().aclose()

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Send verified Chat, Responses, Messages, or System One through the Gateway."""
        if request.method == 'POST' and request.url.copy_with(query=None) == httpx.URL(
            self.base_url
        ).join('systemone'):
            return await self.systemone._send(request)
        return await super().send(request)

    async def _create_session(
        self, model: str
    ) -> _VerifiedSession[VerifiedCompletionResult, AttestationVerificationResult]:
        fetched = await self._attestation_client.fetch_gateway_attestation(
            signing_algo=self._signing_algo,
            include_spki_fingerprint=self._gateway_options.include_spki_fingerprint,
        )
        # Pin evidence requests to the observed TLS peer, not the report's claim.
        # The peer only becomes trusted after Gateway verification succeeds.
        fingerprint = fetched.client_binding.spki_fingerprint
        if self._gateway_options.include_spki_fingerprint:
            if fingerprint is None:
                raise verification_failure('binding.spki_fingerprint_required')
        else:
            fingerprint = None
        client = self._http_clients.get(fingerprint)
        if client is None:
            client = self._create_gateway_client(fingerprint)
            self._http_clients[fingerprint] = client
        attestations = _SessionAttestationClient(
            client, api_key=self._api_key, base_url=self.base_url, headers=self._headers
        )
        (gateway, key_config), models = await gather_cancel_on_error(
            self._verify_gateway(fetched), self._verify_models(model, attestations)
        )
        selected = next(
            (
                item
                for item in models
                if item.signer.signing_algo == self._signing_algo
                and item.signing_public_key is not None
            ),
            None,
        )
        model_key = None
        if selected is not None and selected.signing_public_key is not None:
            model_key = E2eeModelKey(
                signing_algo=self._signing_algo, public_key=selected.signing_public_key
            )
        elif models:
            raise verification_failure('e2ee.model_public_key_required')

        def verify_response(
            id: str,
            request_body: bytes,
            response_body: bytes,
            signature: CompletionSignature,
        ) -> VerifiedCompletionResult:
            if signature.kind == 'provider_tee':
                if selected is None:
                    raise verification_failure(
                        'signature.kind_mismatch',
                        {'expected': 'gateway', 'actual': signature.kind},
                    )
                verify_model_response(request_body, response_body, signature, selected)
                return VerifiedModelCompletionResult(
                    id=id,
                    signature=signature,
                    attestation=selected,
                )
            verify_gateway_response(request_body, response_body, signature, gateway)
            return VerifiedGatewayCompletionResult(
                id=id, signature=signature, attestation=gateway
            )

        return _VerifiedSession(
            model_key=model_key,
            http_client=self._completion_client(client, key_config),
            attestation_client=attestations,
            verify_response=verify_response,
            attestation_result=AttestationVerificationResult(
                gateway=gateway, models=models, verified_at=int(time() * 1000)
            ),
        )

    async def _verify_gateway(
        self, fetched: FetchedGatewayAttestation
    ) -> tuple[VerifiedGatewayAttestation, bytes | None]:
        gateway = await verify_gateway_attestation(
            fetched.attestation,
            fetched.client_binding,
            policy=self._gateway_options.policy,
            verifiers=self._gateway_options.verifiers,
        )
        if gateway.signer.signing_algo != self._signing_algo:
            raise verification_failure('signature.signer_mismatch')
        key_config = None
        if self._ohttp:
            if fetched.attestation.ohttp_attestation is None:
                raise verification_failure('ohttp.attestation_required')
            key_config = verify_ohttp_key_config(
                fetched.attestation.ohttp_attestation, gateway.signer
            )
        return gateway, key_config

    async def _verify_models(
        self, model: str, client: AttestationClient
    ) -> tuple[VerifiedModelAttestation, ...]:
        metadata = await client.fetch_model_metadata(model)
        if metadata.provider_type != 'vllm' or not metadata.attestation_supported:
            if (
                self._e2ee
                or self._deployment_policy is not None
                or self._model_options.policy is not None
                or (
                    self._model_options.verifiers is not None
                    and self._model_options.verifiers.deployment is not None
                )
            ):
                raise verification_failure('policy.model_attestation_required')
            return ()
        fetched = await client.fetch_model_attestations(
            model, signing_algo=self._signing_algo
        )
        if not fetched.attestations:
            raise verification_failure('policy.model_attestation_required')
        verifiers = self._get_model_verifiers(model)
        return tuple(
            await gather_cancel_on_error(
                *(
                    verify_model_attestation(
                        report,
                        fetched.client_binding,
                        policy=self._model_options.policy,
                        verifiers=verifiers,
                    )
                    for report in fetched.attestations
                )
            )
        )

    def _create_gateway_client(
        self, peer_spki_fingerprint: str | None
    ) -> httpx.AsyncClient:
        if peer_spki_fingerprint is not None:
            return create_pinned_tls_client(peer_spki_fingerprint)
        return httpx.AsyncClient(timeout=None)


class _CapturedResponseStream(httpx.AsyncByteStream):
    """Capture wire bytes under consumer backpressure, before E2EE decryption."""

    def __init__(
        self,
        response: httpx.Response,
        response_body: asyncio.Future[bytes],
        register: Callable[[str], None],
        client: _VerifiedInferenceClient,
        *,
        responses: bool = False,
        messages: bool = False,
    ) -> None:
        self._response = response
        self._response_body = response_body
        self._register = register
        self._client = client
        self._responses = responses
        self._messages = messages
        self._chunks: list[bytes] = []
        self._reader = response.aiter_bytes()
        self._content_type = response.headers.get('content-type', '')
        self._streaming = self._content_type.lower().startswith('text/event-stream')
        self._decoder = codecs.getincrementaldecoder('utf-8-sig')()
        self._pending = ''
        self._registered = False
        self._done = False
        self._drain_task: asyncio.Task[None] | None = None

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        try:
            chunk = await anext(self._reader)
            self._capture(chunk)
            return chunk
        except StopAsyncIteration:
            try:
                self._complete()
            except BaseException as error:
                self._fail(error)
                raise
            finally:
                await self._response.aclose()
            raise
        except BaseException as error:
            self._fail(error)
            await self._response.aclose()
            raise

    def _capture(self, chunk: bytes) -> None:
        self._chunks.append(chunk)
        if not self._streaming:
            return
        self._pending += self._decoder.decode(chunk)
        parsed = take_complete_sse_records(self._pending)
        self._pending = parsed.pending
        for record in parsed.records:
            for data in get_sse_data_records(record.value):
                if data == '[DONE]':
                    self._done = True
                elif self._messages and data:
                    try:
                        value = json.loads(data)
                        if value.get('type') == 'message_stop':
                            self._done = True
                        if (
                            value.get('type') == 'message_start'
                            and not self._registered
                        ):
                            self._register(
                                CompletionResponseIdSchema.model_validate(
                                    value.get('message')
                                ).id
                            )
                            self._registered = True
                    except (ValueError, ValidationError, AttributeError):
                        continue
                elif data and not self._registered:
                    try:
                        value = json.loads(data)
                        if self._responses:
                            value = (
                                value.get('response')
                                if isinstance(value, dict)
                                else None
                            )
                        completion_id = CompletionResponseIdSchema.model_validate(
                            value
                        ).id
                    except (ValueError, ValidationError):
                        continue
                    self._register(completion_id)
                    self._registered = True

    def _complete(self) -> None:
        if self._response_body.done():
            return
        body = b''.join(self._chunks)
        if self._messages and self._streaming:
            _validate_message_stream(body)
        if not self._registered:
            self._register(_completion_id(body, self._content_type, self._responses))
            self._registered = True
        self._response_body.set_result(body)
        self._chunks.clear()

    def _fail(self, cause: BaseException) -> None:
        if not self._response_body.done():
            self._response_body.set_exception(
                cause
                if isinstance(cause, (ApiError, VerificationError))
                else api_failure(
                    'api.transport_failed',
                    {'resource': 'completion', 'reason': 'response_body'},
                    retryable=True,
                    cause=cause,
                )
            )
            self._chunks.clear()

    async def aclose(self) -> None:
        if self._drain_task is not None:
            return
        if not self._response_body.done():
            if self._done:
                # OpenAI stops exposing events at [DONE]. Retain any trailing
                # wire bytes without delaying presentation of the completed
                # stream. Only verify_response waits for this tail.
                self._drain_task = asyncio.create_task(self._drain())
                self._client._drains.add(self._drain_task)
                self._drain_task.add_done_callback(self._client._drains.discard)
                return
            else:
                self._fail(RuntimeError('Response body was closed before completion'))
        await self._response.aclose()

    async def _drain(self) -> None:
        try:
            async for chunk in self._reader:
                self._capture(chunk)
            self._complete()
        except asyncio.CancelledError as error:
            self._fail(error)
            raise
        except Exception as error:  # noqa: BLE001
            # Forward background reader failures to verify_response's future.
            self._fail(error)
        finally:
            await self._response.aclose()


def _completion_id(body: bytes, content_type: str, responses: bool = False) -> str:
    try:
        if content_type.lower().startswith('text/event-stream'):
            for data in get_sse_data_records(body.decode('utf-8-sig')):
                if data and data != '[DONE]':
                    value = json.loads(data)
                    if responses:
                        value = (
                            value.get('response') if isinstance(value, dict) else None
                        )
                    try:
                        return CompletionResponseIdSchema.model_validate(value).id
                    except ValidationError:
                        continue
        else:
            return CompletionResponseIdSchema.model_validate_json(body).id
    except (ValueError, UnicodeDecodeError) as error:
        raise _invalid_completion_id(error) from error
    raise _invalid_completion_id()


def _validate_message_stream(body: bytes) -> None:
    """Only a complete message_start/message_stop sequence can have a receipt."""
    parsed = take_complete_sse_records(body.decode('utf-8-sig'), eof=True)
    started = False
    stopped = False
    if parsed.pending:
        raise _invalid_completion_id()
    for record in parsed.records:
        event_name = get_sse_event(record.value)
        if event_name == 'error':
            raise _invalid_completion_id()
        for data in get_sse_data_records(record.value):
            if not data:
                continue
            try:
                event = json.loads(data)
                kind = event.get('type')
                if (
                    not isinstance(kind, str)
                    or not kind
                    or kind == 'error'
                    or stopped
                    or (event_name is not None and event_name != kind)
                ):
                    raise _invalid_completion_id()
                if kind == 'message_start':
                    if started:
                        raise _invalid_completion_id()
                    CompletionResponseIdSchema.model_validate(event.get('message'))
                    started = True
                if kind == 'message_stop':
                    stopped = True
            except (ValueError, AttributeError) as error:
                raise _invalid_completion_id(error) from error
    if not started or not stopped:
        raise _invalid_completion_id()


def _invalid_completion_id(cause: BaseException | None = None) -> ApiError:
    return api_failure(
        'api.invalid_response',
        {
            'path': 'completion response ID or SSE lifecycle',
            'expected': 'a non-empty ID and a complete valid stream',
            'actual': 'missing or invalid',
        },
        cause=cause,
    )


def _decoded_headers(headers: httpx.Headers) -> httpx.Headers:
    result = httpx.Headers(headers)
    result.pop('content-encoding', None)
    result.pop('content-length', None)
    return result


def _observe_exception(future: asyncio.Future) -> None:
    if not future.cancelled():
        future.exception()
