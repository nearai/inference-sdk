"""Verified Chat Completions and an HTTP client usable by AsyncOpenAI."""

from __future__ import annotations

import asyncio
import codecs
import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, replace
from time import monotonic

import httpx
from openai import AsyncOpenAI
from pydantic import ValidationError

from ..schemas import CompletionResponseIdSchema
from ..types.attestation_common import SigningAlgo
from ..types.cloud_api import DEFAULT_NEAR_AI_CLOUD_BASE_URL, NO_ALIASING_HEADER
from ..types.e2ee import E2eeModelKey
from ..types.inference_client import (
    DeploymentPolicy,
    GatewayVerificationOptions,
    ModelVerificationOptions,
    VerifiedCompletionReceipt,
    VerifiedGatewayCompletionReceipt,
    VerifiedModelCompletionReceipt,
)
from ..types.verification import (
    GatewayTlsBinding,
    MeasuredDeployment,
    ModelAttestationVerifiers,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
)
from ..utils.common import maybe_await
from ..utils.errors import (
    ApiError,
    VerificationError,
    api_failure,
    verification_failure,
)
from ..utils.fetch import FetchResponse
from ..utils.sse import get_sse_data_records, take_complete_sse_records
from .attestation_gateway import verify_gateway_attestation
from .attestation_model import verify_model_attestation
from .chat import verify_gateway_response, verify_model_response
from .cloud_api import AttestationClient, _validate_base_url
from .e2ee_request import (
    decode_chat_request,
    prepare_e2ee_chat_request,
    remove_e2ee_headers,
)
from .pinned_tls import create_pinned_tls_client


DEFAULT_CACHE_TIME_TO_LIVE_MS = 60 * 60 * 1000
_OPENAI_PLACEHOLDER = 'nearai-inference-sdk-internal'


@dataclass(frozen=True)
class _VerifiedSession:
    gateway: VerifiedGatewayAttestation
    model: VerifiedModelAttestation
    model_key: E2eeModelKey
    http_client: httpx.AsyncClient
    attestation_client: AttestationClient


@dataclass
class _CompletionRecord:
    request_body: bytes
    response_body: asyncio.Future[bytes]
    session: _VerifiedSession
    content_type: str
    verification: asyncio.Task[VerifiedCompletionReceipt] | None = None
    expiry: asyncio.TimerHandle | None = None


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
    def __init__(self, client: InferenceClient) -> None:
        self._client = client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._client.send(request)

    async def aclose(self) -> None:
        await self._client._close_sessions()


class InferenceClient:
    """Verify before sending Chat requests, then verify responses explicitly.

    ``chat.completions.create`` is the standard asynchronous OpenAI interface.
    Pass ``http_client`` to an external ``AsyncOpenAI`` to use the same verified
    transport. Both paths retain encrypted wire bytes for ``verify_response``.
    Use ``async with`` or call ``aclose`` to release connections and caches.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL,
        headers: Mapping[str, str] | None = None,
        e2ee: bool = True,
        signing_algo: SigningAlgo = 'ed25519',
        attestation_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        response_cache_time_to_live_ms: float = DEFAULT_CACHE_TIME_TO_LIVE_MS,
        gateway_verification: GatewayVerificationOptions | None = None,
        model_verification: ModelVerificationOptions | None = None,
        deployment_policy: DeploymentPolicy | None = None,
    ) -> None:
        self.base_url = _validate_base_url(base_url).rstrip('/') + '/'
        self._api_key = api_key
        self._headers = httpx.Headers(headers)
        if api_key is not None:
            self._headers['authorization'] = f'Bearer {api_key}'
            self._headers.pop('api-key', None)
        self._signing_algo = signing_algo
        self._e2ee = e2ee
        self._attestation_ttl = attestation_cache_time_to_live_ms / 1000
        self._response_ttl = response_cache_time_to_live_ms / 1000
        self._gateway_options = gateway_verification or GatewayVerificationOptions()
        self._model_options = model_verification or ModelVerificationOptions()
        self._deployment_policy = deployment_policy
        self._attestation_client = AttestationClient(
            api_key, base_url=self.base_url, headers=self._headers
        )
        self._sessions: dict[str, tuple[float, _VerifiedSession]] = {}
        self._pending: dict[str, asyncio.Task[_VerifiedSession]] = {}
        self._gateway_clients: dict[str | None, httpx.AsyncClient] = {}
        self._completions: dict[str, _CompletionRecord] = {}
        self._drains: set[asyncio.Task[None]] = set()
        self.http_client = httpx.AsyncClient(
            transport=_InferenceTransport(self), timeout=None
        )
        # The wrapper requires a key even when an aggregator uses custom
        # authentication. send() replaces its headers with this configuration.
        self._openai = AsyncOpenAI(
            api_key=api_key or _OPENAI_PLACEHOLDER,
            base_url=self.base_url,
            http_client=self.http_client,
        )
        self.chat = self._openai.chat

    async def __aenter__(self) -> InferenceClient:
        return self

    async def __aexit__(self, *_args) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self.http_client.aclose()

    async def _close_sessions(self) -> None:
        pending = [*self._pending.values(), *self._drains]
        pending.extend(
            record.verification
            for record in self._completions.values()
            if record.verification is not None
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for record in self._completions.values():
            if record.expiry is not None:
                record.expiry.cancel()
        await asyncio.gather(
            *(client.aclose() for client in self._gateway_clients.values())
        )
        self._gateway_clients.clear()
        self._sessions.clear()
        self._completions.clear()

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Send a Chat request; the returned body can be read or streamed.

        This is the low-level counterpart of ``http_client.send``. Consume or
        close its response, and finish a stream before calling verify_response.
        """

        expected = httpx.URL(self.base_url).join('chat/completions')
        if request.method != 'POST' or request.url.copy_with(query=None) != expected:
            raise api_failure(
                'api.invalid_input',
                {
                    'field': 'request',
                    'reason': 'unsupported_value',
                    'expected': 'a POST to the configured Chat Completions endpoint',
                },
            )
        parsed = await decode_chat_request(request)
        body = request.content
        session = await self._start_verification(parsed['model'])
        headers = httpx.Headers(self._headers)
        headers.update(request.headers)
        # Use the same configured authorization for evidence, Chat, and signatures,
        # including when an external OpenAI client supplies its own API key.
        if 'authorization' in self._headers:
            headers['authorization'] = self._headers['authorization']
        else:
            headers.pop('authorization', None)
        if self._api_key is not None:
            headers.pop('api-key', None)
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
            prepared = await prepare_e2ee_chat_request(
                prepared_request, session.model_key
            )
            prepared_request = prepared.request
        else:
            remove_e2ee_headers(prepared_request.headers)
            prepared_request.headers[NO_ALIASING_HEADER] = 'true'
            prepared_request.headers['x-model-pub-key'] = session.model_key.public_key
        try:
            response = await session.http_client.send(prepared_request, stream=True)
        except (ApiError, VerificationError):
            raise
        except httpx.HTTPError as error:
            raise api_failure(
                'api.transport_failed',
                {
                    'resource': 'completion',
                    'reason': 'request',
                },
                retryable=True,
                cause=error,
            ) from error
        if not response.is_success:
            return response
        response_body = asyncio.get_running_loop().create_future()
        # Verification is explicit: retaining an error must not emit an
        # unhandled-future warning when a caller only consumes the chat.
        response_body.add_done_callback(_observe_exception)
        record = _CompletionRecord(
            request_body=await prepared_request.aread(),
            response_body=response_body,
            session=session,
            content_type=response.headers.get('content-type', ''),
        )
        captured = httpx.Response(
            response.status_code,
            headers=_decoded_headers(response.headers),
            stream=_CapturedResponseStream(response, record, self),
            extensions=response.extensions,
            request=prepared_request,
        )
        if prepared is not None:
            return await prepared.decrypt_response(captured)
        return captured

    async def verify_response(self, completion_id: str) -> VerifiedCompletionReceipt:
        """Verify a retained response against the evidence used before sending."""

        record = self._completions.get(completion_id)
        if record is None:
            raise api_failure('api.completion_not_found')
        if record.verification is None:
            record.verification = asyncio.create_task(self._verify_record(record))
            record.verification.add_done_callback(_observe_exception)
        task = record.verification
        try:
            return await asyncio.shield(task)
        except ApiError as error:
            if error.retryable and record.verification is task:
                record.verification = None
            raise

    async def _verify_record(
        self, record: _CompletionRecord
    ) -> VerifiedCompletionReceipt:
        body = await record.response_body
        completion_id = _completion_id(body, record.content_type)
        signature = await record.session.attestation_client.fetch_completion_signature(
            completion_id, signing_algo=record.session.model_key.signing_algo
        )
        if signature.kind == 'provider_tee':
            verify_model_response(
                record.request_body, body, signature, record.session.model
            )
            return VerifiedModelCompletionReceipt(
                completion_id=completion_id,
                signature=signature,
                attestation=record.session.model,
            )
        verify_gateway_response(
            record.request_body, body, signature, record.session.gateway
        )
        return VerifiedGatewayCompletionReceipt(
            completion_id=completion_id,
            signature=signature,
            attestation=record.session.gateway,
        )

    async def _start_verification(self, model: str) -> _VerifiedSession:
        now = monotonic()
        self._sessions = {
            name: value for name, value in self._sessions.items() if value[0] > now
        }
        if self._attestation_ttl != 0 and model in self._sessions:
            return self._sessions[model][1]
        task = self._pending.get(model)
        if task is None:
            task = asyncio.create_task(self._create_session(model))
            self._pending[model] = task

            def finished(completed: asyncio.Task[_VerifiedSession]) -> None:
                self._pending.pop(model, None)
                if not completed.cancelled() and completed.exception() is None:
                    if self._attestation_ttl != 0:
                        self._sessions[model] = (
                            monotonic() + self._attestation_ttl,
                            completed.result(),
                        )

            task.add_done_callback(finished)
        # Cancelling one chat must not cancel shared verification for others.
        return await asyncio.shield(task)

    async def _create_session(self, model: str) -> _VerifiedSession:
        fetched = await self._attestation_client.fetch_gateway_attestation(
            signing_algo=self._signing_algo,
            include_spki_fingerprint=self._gateway_options.include_spki_fingerprint,
        )
        gateway = await verify_gateway_attestation(
            fetched.attestation,
            fetched.client_binding,
            policy=self._gateway_options.policy,
            verifiers=self._gateway_options.verifiers,
        )
        fingerprint = gateway.tls_binding.spki_fingerprint
        client = self._gateway_clients.get(fingerprint)
        if client is None:
            client = self._create_gateway_client(gateway.tls_binding)
            self._gateway_clients[fingerprint] = client
        attestations = _SessionAttestationClient(
            client,
            api_key=self._api_key,
            base_url=self.base_url,
            headers=self._headers,
        )
        fetched_models = await attestations.fetch_model_attestations(
            model,
            signing_algo=self._signing_algo,
        )
        if not fetched_models.attestations:
            raise verification_failure('policy.model_attestation_required')
        verifiers = self._model_options.verifiers
        if self._deployment_policy is not None:
            original = None if verifiers is None else verifiers.deployment

            async def deployment_policy(deployment: MeasuredDeployment) -> None:
                if original is not None:
                    await maybe_await(original(deployment))
                await maybe_await(self._deployment_policy(model, deployment))

            verifiers = replace(
                verifiers or ModelAttestationVerifiers(), deployment=deployment_policy
            )
        models = await asyncio.gather(
            *(
                verify_model_attestation(
                    raw,
                    fetched_models.client_binding,
                    policy=self._model_options.policy,
                    verifiers=verifiers,
                )
                for raw in fetched_models.attestations
            )
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
        if selected is None:
            raise verification_failure('e2ee.model_public_key_required')
        return _VerifiedSession(
            gateway,
            selected,
            E2eeModelKey(
                signing_algo=self._signing_algo, public_key=selected.signing_public_key
            ),
            client,
            attestations,
        )

    def _create_gateway_client(
        self, tls_binding: GatewayTlsBinding
    ) -> httpx.AsyncClient:
        if tls_binding.kind == 'attested':
            return create_pinned_tls_client(tls_binding.spki_fingerprint)
        return httpx.AsyncClient(timeout=None)

    def _register(self, completion_id: str, record: _CompletionRecord) -> None:
        previous = self._completions.get(completion_id)
        if previous is not None and previous.expiry is not None:
            previous.expiry.cancel()
        self._completions[completion_id] = record

        def settled(_future: asyncio.Future[bytes]) -> None:
            def expire() -> None:
                if self._completions.get(completion_id) is record:
                    del self._completions[completion_id]

            record.expiry = asyncio.get_running_loop().call_later(
                self._response_ttl, expire
            )

        record.response_body.add_done_callback(settled)


class _CapturedResponseStream(httpx.AsyncByteStream):
    """Capture wire bytes under consumer backpressure, before E2EE decryption."""

    def __init__(
        self,
        response: httpx.Response,
        record: _CompletionRecord,
        client: InferenceClient,
    ) -> None:
        self._response = response
        self._record = record
        self._client = client
        self._chunks: list[bytes] = []
        self._reader = response.aiter_bytes()
        self._streaming = record.content_type.lower().startswith('text/event-stream')
        self._decoder = codecs.getincrementaldecoder('utf-8')()
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
                elif data and not self._registered:
                    try:
                        completion_id = CompletionResponseIdSchema.model_validate_json(
                            data
                        ).id
                    except ValidationError:
                        continue
                    self._client._register(completion_id, self._record)
                    self._registered = True

    def _complete(self) -> None:
        if self._record.response_body.done():
            return
        body = b''.join(self._chunks)
        if not self._registered:
            self._client._register(
                _completion_id(body, self._record.content_type), self._record
            )
            self._registered = True
        self._record.response_body.set_result(body)
        self._chunks.clear()

    def _fail(self, cause: BaseException) -> None:
        if not self._record.response_body.done():
            self._record.response_body.set_exception(
                api_failure(
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
        if not self._record.response_body.done():
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
        except BaseException as error:
            self._fail(error)
        finally:
            await self._response.aclose()


def _completion_id(body: bytes, content_type: str) -> str:
    try:
        if content_type.lower().startswith('text/event-stream'):
            for data in get_sse_data_records(body.decode('utf-8')):
                if data and data != '[DONE]':
                    value = json.loads(data)
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
