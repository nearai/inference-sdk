"""Verified Chat Completions and an HTTP client usable by AsyncOpenAI."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, replace
from time import monotonic, time
from typing import TYPE_CHECKING, Self

import httpx
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
from ..utils.sse import SseDecoder, get_sse_data_records
from .attestation_gateway import verify_gateway_attestation
from .attestation_model import verify_model_attestation
from .body_limit import (
    BufferedResponse,
    read_bounded_request_body,
    require_body_size,
    require_identity_encoding,
)
from .chat import verify_gateway_response, verify_model_response
from .cloud_api import (
    AttestationClient,
    _ApiClient,
    _validate_base_url,
)
from .e2ee_chat import measure_e2ee_chat_request_bytes
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
class _ReceiptVerification[Result]:
    task: asyncio.Task[Result]
    waiters: int = 0


@dataclass(eq=False)
class _ResponseRecord[Result, AttestationResult]:
    request_body: bytes
    response_body: asyncio.Future[bytes]
    session: _VerifiedSession[Result, AttestationResult]
    gateway_only: bool = False
    verification: _ReceiptVerification[Result] | None = None
    expiry: asyncio.TimerHandle | None = None
    retained_bytes: int | None = None
    settle: Callable[[], None] | None = None


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
    def __init__(self, client: _VerifiedInferenceClient) -> None:
        self._client = client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._client.send(request)


class _VerifiedInferenceClient[Result, AttestationResult]:
    """Verify before sending Chat requests, then verify responses explicitly.

    ``chat.completions.create`` is the standard asynchronous OpenAI interface.
    Pass ``http_client`` to an external ``AsyncOpenAI`` to use the same verified
    transport. Both paths retain encrypted wire bytes for ``verify_response``.
    Use ``async with`` or call ``aclose`` to release connections and caches.
    """

    _supports_responses = False

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
        max_body_bytes: int = 64 * 1024 * 1024,
        max_cache_entries: int = 128,
        max_receipt_cache_bytes: int = 64 * 1024 * 1024,
        model_verification: ModelVerificationOptions | None = None,
        deployment_policy: DeploymentPolicy | None = None,
    ) -> None:
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
        for field, value in {
            'max_body_bytes': max_body_bytes,
            'max_cache_entries': max_cache_entries,
            'max_receipt_cache_bytes': max_receipt_cache_bytes,
        }.items():
            if type(value) is not int or value <= 0:
                raise api_failure(
                    'api.invalid_input',
                    {
                        'field': field,
                        'reason': 'unsupported_value',
                        'expected': 'a positive integer',
                    },
                )
        self._max_body_bytes = max_body_bytes
        self._max_cache_entries = max_cache_entries
        self._max_receipt_cache_bytes = max_receipt_cache_bytes
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
        self._pending_waiters: dict[
            asyncio.Task[_VerifiedSession[Result, AttestationResult]], int
        ] = {}
        self._http_clients: dict[str | tuple[str, ...] | None, httpx.AsyncClient] = {}
        self._responses: dict[str, _ResponseRecord[Result, AttestationResult]] = {}
        self._response_verifications: dict[
            asyncio.Task[Result], _ResponseRecord[Result, AttestationResult]
        ] = {}
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
        # Include abandoned tasks until their cancellation cleanup has finished.
        pending = [
            *self._pending_waiters,
            *self._drains,
            *self._response_verifications,
        ]
        for task in pending:
            if not task.cancelling():
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
        if request.method != 'POST' or (
            actual != expected and not (responses and self._supports_responses)
        ):
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'request',
                    'reason': 'unsupported_value',
                    'expected': 'a POST to a supported inference creation endpoint',
                },
            )
        if responses and self._e2ee:
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'e2ee',
                    'reason': 'unsupported_value',
                    'expected': 'field-level E2EE disabled for Responses',
                },
            )
        request_limit = self._max_body_bytes
        # E2EE reserializes JSON; receipt capacity applies to its wire body below.
        if self._response_ttl != 0 and not self._e2ee:
            # Retained plaintext receipts also need space for a nonempty response.
            request_limit = min(request_limit, self._max_receipt_cache_bytes - 1)
        body = await read_bounded_request_body(request, request_limit)
        request = httpx.Request(
            request.method,
            request.url,
            headers=request.headers,
            content=body,
            extensions=request.extensions,
        )
        parsed = await decode_chat_request(request)
        if self._e2ee:
            self._response_byte_limit(
                measure_e2ee_chat_request_bytes(parsed, self._signing_algo)
            )
        headers = self._request_headers(request.headers)
        # Automatic decompression can allocate beyond the body budget before
        # aiter_bytes() yields. Require the signed, uncompressed representation.
        headers['accept-encoding'] = 'identity'
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
            if session.model_key is not None:
                prepared_request.headers['x-model-pub-key'] = (
                    session.model_key.public_key
                )
        self._response_byte_limit(len(prepared_request.content))
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
        try:
            require_identity_encoding(response)
        except ApiError:
            await response.aclose()
            raise
        if not response.is_success:
            return httpx.Response(
                response.status_code,
                headers=_decoded_headers(response.headers),
                stream=_BoundedErrorStream(response, self._max_body_bytes),
                extensions=response.extensions,
                request=prepared_request,
            )
        response_body = asyncio.get_running_loop().create_future()
        response_body.add_done_callback(_observe_exception)
        request_body = await prepared_request.aread()

        def register(completion_id: str) -> None:
            self._register_response(
                completion_id,
                request_body,
                response_body,
                session,
                gateway_only=responses,
            )

        captured = BufferedResponse(
            response.status_code,
            headers=_decoded_headers(response.headers),
            stream=_CapturedResponseStream(
                response, response_body, register, self, responses=responses
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
        # Use the same configured authorization for evidence, Chat, and signatures,
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

        record = self._responses.get(id)
        if record is None:
            raise api_failure('api.completion_not_found')
        while record.verification is not None and record.verification.task.cancelling():
            verification = record.verification
            await asyncio.shield(
                asyncio.gather(verification.task, return_exceptions=True)
            )
            if record.verification is verification:
                record.verification = None
        if record.verification is None:
            if (
                sum(not task.done() for task in self._response_verifications)
                >= self._max_cache_entries
            ):
                raise api_failure(
                    'api.invalid_input',
                    {
                        'field': 'id',
                        'reason': 'unsupported_value',
                        'expected': 'fewer concurrent receipt verifications',
                    },
                )
            task = asyncio.create_task(self._verify_record(id, record))
            record.verification = _ReceiptVerification(task)
            self._response_verifications[task] = record
            task.add_done_callback(self._response_verifications.pop)
            task.add_done_callback(_observe_exception)
        verification = record.verification
        verification.waiters += 1
        try:
            return await asyncio.shield(verification.task)
        finally:
            verification.waiters -= 1
            if verification.waiters == 0 and not verification.task.done():
                if not verification.task.cancelling():
                    verification.task.cancel()
                await asyncio.shield(
                    asyncio.gather(verification.task, return_exceptions=True)
                )
                if record.verification is verification:
                    record.verification = None

    async def _verify_record(
        self, id: str, record: _ResponseRecord[Result, AttestationResult]
    ) -> Result:
        try:
            # Cancelling verification must not cancel the captured response.
            body = await asyncio.shield(record.response_body)
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
            # Leave a newer verification intact if this task was abandoned.
            if (
                record.verification is not None
                and record.verification.task is asyncio.current_task()
                and (
                    error.retryable
                    or error.failure.code == 'api.completion_signature_unavailable'
                )
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
            if (
                sum(not pending.done() for pending in self._pending_waiters)
                >= self._max_cache_entries
            ):
                raise api_failure(
                    'api.invalid_input',
                    {
                        'field': 'model',
                        'reason': 'unsupported_value',
                        'expected': 'fewer concurrent preflights',
                    },
                )
            task = asyncio.create_task(self._create_session(model))
            self._pending[cache_key] = task

            def finished(
                completed: asyncio.Task[_VerifiedSession[Result, AttestationResult]],
            ) -> None:
                self._pending_waiters.pop(completed, None)
                if self._pending.get(cache_key) is not completed:
                    _observe_exception(completed)
                    return
                self._pending.pop(cache_key, None)
                if (
                    not completed.cancelled()
                    and completed.exception() is None
                    and self._attestation_ttl != 0
                    and not self._chat_client.is_closed
                ):
                    while len(self._sessions) >= self._max_cache_entries:
                        del self._sessions[next(iter(self._sessions))]
                    self._sessions[cache_key] = (
                        monotonic() + self._attestation_ttl,
                        completed.result(),
                    )

            task.add_done_callback(finished)
        self._pending_waiters[task] = self._pending_waiters.get(task, 0) + 1
        try:
            # Cancelling one caller must not cancel verification still in use.
            return await asyncio.shield(task)
        finally:
            if task in self._pending_waiters:
                self._pending_waiters[task] -= 1
                if self._pending_waiters[task] == 0 and not task.done():
                    if self._pending.get(cache_key) is task:
                        del self._pending[cache_key]
                    task.cancel()

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

    def _response_byte_limit(self, request_size: int) -> int:
        require_body_size(request_size, self._max_body_bytes)
        if self._response_ttl == 0:
            return self._max_body_bytes
        if request_size >= self._max_receipt_cache_bytes:
            raise api_failure('api.body_too_large')
        return min(self._max_body_bytes, self._max_receipt_cache_bytes - request_size)

    def _evict_response(self, id: str) -> None:
        record = self._responses.pop(id, None)
        if record is not None and record.expiry is not None:
            record.expiry.cancel()

    def _register_response(
        self,
        id: str,
        request_body: bytes,
        response_body: asyncio.Future[bytes],
        session: _VerifiedSession[Result, AttestationResult],
        *,
        gateway_only: bool = False,
    ) -> None:
        """Retain completed wire bytes under FIFO count/byte limits and expiry."""
        if self._chat_client.is_closed:
            raise RuntimeError('InferenceClient is closed')
        if self._response_ttl == 0:
            return
        record = _ResponseRecord(
            request_body, response_body, session, gateway_only=gateway_only
        )
        self._evict_response(id)
        self._responses[id] = record

        def settled(future: asyncio.Future[bytes]) -> None:
            record.settle = None
            if record.retained_bytes is not None or self._chat_client.is_closed:
                return
            if future.cancelled() or future.exception() is not None:
                if self._responses.get(id) is record:
                    del self._responses[id]
                return
            record.retained_bytes = len(request_body) + len(future.result())
            if self._responses.get(id) is record:
                # Completion order determines FIFO, regardless of stream start time.
                del self._responses[id]
                self._responses[id] = record
            completed = [
                (key, entry)
                for key, entry in self._responses.items()
                if entry.retained_bytes is not None
            ]
            active = {
                entry
                for task, entry in self._response_verifications.items()
                if not task.done()
            }
            retained = sum(
                entry.retained_bytes or 0
                for entry in active | {entry for _, entry in completed}
            )
            while completed and (
                len(completed) > self._max_cache_entries
                or retained > self._max_receipt_cache_bytes
            ):
                key, entry = completed.pop(0)
                if entry not in active:
                    retained -= entry.retained_bytes or 0
                self._evict_response(key)
            if self._responses.get(id) is not record:
                return

            def expire() -> None:
                if self._responses.get(id) is record:
                    self._evict_response(id)

            record.expiry = asyncio.get_running_loop().call_later(
                self._response_ttl, expire
            )

        record.settle = lambda: settled(response_body)
        # System One already has a completed body; apply eviction before returning.
        if response_body.done():
            settled(response_body)
        else:
            response_body.add_done_callback(settled)


class InferenceClient(
    _VerifiedInferenceClient[VerifiedCompletionResult, AttestationVerificationResult]
):
    """Gateway Chat and System One with preflight and explicit response verification.

    E2EE is opt-in. NEAR TEE models require model evidence; Incognito models
    verify only the Gateway. All calls share the configured authentication.
    """

    _supports_responses = True

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
        max_body_bytes: int = 64 * 1024 * 1024,
        max_cache_entries: int = 128,
        max_receipt_cache_bytes: int = 64 * 1024 * 1024,
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
            max_body_bytes=max_body_bytes,
            max_cache_entries=max_cache_entries,
            max_receipt_cache_bytes=max_receipt_cache_bytes,
            model_verification=model_verification,
            deployment_policy=deployment_policy,
        )
        self._gateway_options = gateway_verification or GatewayVerificationOptions()
        self.responses = self._openai.responses
        self._attestation_client = AttestationClient(
            api_key, base_url=self.base_url, headers=self._headers
        )
        self.systemone = InferenceSystemOne(self)

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Send verified Chat, Responses, or System One through the Gateway."""
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


class _BoundedErrorStream(httpx.AsyncByteStream):
    """Bound decoded error bodies without retaining them as receipts."""

    def __init__(self, response: httpx.Response, limit: int) -> None:
        self._response = response
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        size = 0
        buffered = bytearray()
        chunk_size = 64 * 1024
        try:
            async for chunk in self._response.aiter_bytes():
                require_body_size(size + len(chunk), self._limit)
                size += len(chunk)
                # HTTPX/OpenAI collect yielded chunks before joining them. Bound
                # their per-chunk overhead as well as the total payload bytes.
                view = memoryview(chunk)
                offset = 0
                while offset < len(view):
                    end = min(len(view), offset + chunk_size - len(buffered))
                    buffered.extend(view[offset:end])
                    offset = end
                    if len(buffered) == chunk_size:
                        yield bytes(buffered)
                        buffered.clear()
            if buffered:
                yield bytes(buffered)
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        await self._response.aclose()


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
    ) -> None:
        self._response = response
        self._response_body = response_body
        self._register = register
        self._client = client
        self._responses = responses
        self._body = bytearray()
        self._limit = client._response_byte_limit(len(response.request.content))
        self._reader = response.aiter_bytes()
        self._content_type = response.headers.get('content-type', '')
        self._streaming = self._content_type.lower().startswith('text/event-stream')
        self._decoder = SseDecoder()
        self._registered = False
        self._done = False
        self._drain_task: asyncio.Task[None] | None = None

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        buffered = bytearray()
        try:
            while True:
                chunk = await anext(self._reader)
                self._capture(chunk)
                if self._streaming:
                    return chunk
                # HTTPX/OpenAI collect JSON chunks before joining them.
                buffered.extend(chunk)
                if len(buffered) >= 64 * 1024:
                    return bytes(buffered)
        except StopAsyncIteration:
            try:
                self._complete()
            except BaseException as error:
                self._fail(error)
                raise
            finally:
                await self._response.aclose()
            if buffered:
                return bytes(buffered)
            raise
        except BaseException as error:
            self._fail(error)
            await self._response.aclose()
            raise

    def _capture(self, chunk: bytes) -> None:
        require_body_size(len(self._body) + len(chunk), self._limit)
        self._body.extend(chunk)
        if not self._streaming:
            return
        for record in self._decoder.feed(chunk):
            for data in get_sse_data_records(record.value):
                if data == '[DONE]':
                    self._done = True
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
        body = bytes(self._body)
        if not self._registered:
            # Complete SSE events were already parsed while capturing the body.
            pending = self._decoder.finish().encode() if self._streaming else body
            self._register(_completion_id(pending, self._content_type, self._responses))
            self._registered = True
        self._response_body.set_result(body)
        # Apply completion limits before exposing EOF to the caller. Future done
        # callbacks otherwise run a loop turn after OpenAI returns parsed JSON.
        for record in tuple(self._client._responses.values()):
            if record.response_body.done() and record.settle is not None:
                record.settle()
        self._body.clear()

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
            self._body.clear()

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
            for data in get_sse_data_records(body.decode('utf-8')):
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


def _invalid_completion_id(cause: BaseException | None = None) -> ApiError:
    return api_failure(
        'api.invalid_response',
        {
            'path': 'Chat Completions response.id',
            'expected': 'a non-empty completion ID',
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
