# NEAR AI Inference SDK for Python

`nearai-inference-sdk` provides OpenAI-compatible Chat Completions with Gateway
and model attestation verification, response signature verification, and optional
encryption. Use the asynchronous `InferenceClient` to get started.

## Install

Requires **Python 3.12 or later**. Clients use `asyncio`; there is no synchronous
Chat client. Install with pip:

```sh
pip install nearai-inference-sdk==0.1.0
```

## Send and verify a Chat completion

Set your NEAR AI Cloud API key in your server environment:

```sh
export NEARAI_API_KEY='your-api-key'
```

Save this example as `chat.py` and run it with `python chat.py`:

```python
import asyncio
import os

from nearai_inference_sdk import InferenceClient


async def main() -> None:
    async with InferenceClient(
        os.environ['NEARAI_API_KEY'],
        e2ee=True,
    ) as client:
        completion = await client.chat.completions.create(
            model='z-ai/glm-5.3-flash',
            messages=[{'role': 'user', 'content': 'Hello!'}],
        )

        # Verify the completion signature before using the answer.
        verified = await client.verify_response(completion.id)
        print(f'Verified {verified.signature_kind} response')
        print(completion.choices[0].message.content or '')


if __name__ == '__main__':
    asyncio.run(main())
```

The client connects to the NEAR AI Cloud Gateway by default. This example enables
E2EE, which encrypts supported Chat fields to an attested model and decrypts its
response. Choose a model that supports NEAR model attestation; E2EE rejects
unsupported models before sending Chat.

Gateway TLS identity verification is enabled by default, and subsequent requests
are pinned to that identity. Reuse a client across requests. The `async with`
block closes its connections and clears retained records; outside a context
manager, call `await client.aclose()` when finished.

## When verification happens

1. **Before sending Chat:** the client verifies Gateway evidence and checks the
   model's attestation support. Supported NEAR TEE models require every returned
   model report to pass. Failed required checks stop the request.
2. **After receiving the response:** call `await client.verify_response(id)` to
   verify its signature. The client retains the exact request and response bytes
   and preflight evidence automatically, including encrypted bytes when E2EE is
   enabled. Applications do not need to capture those bytes themselves.
3. **For streaming:** consume the entire stream before calling `verify_response()`.
   Content displayed before that call succeeds is not yet signature-verified.
   See the [streaming example](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#verified-chat-client).

Optionally call `await client.verify(model)` before the first Chat. It sends no
Chat request and shares Chat's verification cache and in-flight work. It returns
verified Gateway and model evidence with the verification time, preserved on
cache hits. It raises if verification fails and does not verify a particular reply.

Successful deployment verification is cached for 60 minutes per model and endpoint.
Set `attestation_cache_time_to_live_ms=0` to verify before every request. Response
records have a separate 60-minute lifetime starting when the body finishes;
verify replies before records expire and before closing the client. See
[caching and preflight](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#verify-before-the-first-chat-request).

## Verification and encryption

These defaults apply to the Gateway `InferenceClient`:

| Feature | Purpose | Default |
| --- | --- | --- |
| Attestation | Verify Gateway and supported model deployments | Enabled |
| Gateway TLS binding | Pin requests to the attested Gateway identity | Enabled |
| Response verification | Verify exact request and response bytes | Explicit `verify_response()` call |
| E2EE | Encrypt supported Chat fields to the attested model | Disabled; set `e2ee=True` |
| OHTTP | Encrypt the Chat HTTP exchange to the attested Gateway | Disabled; set `ohttp=True` |

Ed25519 is the default signing algorithm; ECDSA is also supported. OHTTP requires
Ed25519 and is independent of field-level E2EE. See
[OHTTP configuration](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#use-ohttp).

Models without supported NEAR model attestation use **Incognito** mode: Gateway
verification only. E2EE and configured model deployment policies reject this
mode. A `provider_tee` signature binds the exact bytes to an attested model
signer; a `gateway` signature binds them to an attested Gateway signer and does
not prove model TEE execution. These checks do not establish a complete chain
through Gateway transformations. See the
[evidence boundary](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#current-evidence-boundary).

Attestation does not approve particular deployments by default. Supply deployment
policies or image provenance policies to enforce your application's approval
criteria. See [policy and trust roots](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#set-policy-and-trust-roots)
and [image build provenance](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#optional-image-build-provenance).

## Use the OpenAI SDK

Pass `inference_client.http_client` to `openai.AsyncOpenAI` to use the same verified
transport for JSON and streaming Chat. Configure credentials on `InferenceClient`
and verify replies through it. See the
[OpenAI integration example](https://github.com/nearai/inference-sdk/blob/main/examples/example-py/gateway/client_openai_sdk.py).
Only Chat Completions are supported; the Responses API is not supported.

## Advanced APIs

- **Manual verification:** `AttestationClient` retrieves evidence and signatures.
  With [standalone functions](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#standalone-workflow),
  your application verifies every model candidate and retains the exact wire bytes.
- **Standalone E2EE:** `prepare_e2ee_chat_request()` encrypts a raw HTTPX Chat
  request and supplies its JSON/SSE decryptor. Key verification and response
  signature verification remain the application's responsibility.
- **Direct endpoints (experimental):** `DirectInferenceClient` and
  `DirectAttestationClient` connect without Gateway verification. Direct TLS
  fingerprint requests are disabled pending complete fleet coverage; normal HTTPS
  verification remains enabled. Use Gateway clients for production. See
  [direct-endpoint limitations](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#direct-model-endpoints).

## System One decisions

`InferenceClient.systemone.create()` sends typed `noul`, `choice`, and `score`
decision requests after Gateway and applicable model verification. Its result
provides `data` and `decision_id` from the `X-Generation-Id` header, including for
hosted responses without a JSON ID. Call `client.verify_response(result.decision_id)`
to verify the captured bytes. Chat and System One share caching, response retention,
and verification retries, with separate attestation sessions for each endpoint.
System One does not support streaming, E2EE, or OHTTP and never automatically
repeats inference. Receipt lookups can be retried without sending another decision.

## Documentation

- [Verification guide](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md):
  streaming, encryption, proxies, policies, TLS binding, and error handling.
- [API reference](https://github.com/nearai/inference-sdk/blob/main/py/docs/api-reference.md):
  client options, public functions, defaults, and result fields.
- [Runnable Python examples](https://github.com/nearai/inference-sdk/blob/main/examples/README.md#python):
  Gateway and direct clients, standalone verification, and OpenAI integration.
- [Error handling](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#handle-retrieval-and-verification-errors):
  SDK errors, OpenAI exception wrapping, and receipt-only retries.

## Development checks

From `py/`, run `uv sync` and `make lint` for formatting, lint, and deterministic
unit tests; `uv build` creates the distributions. Live service checks are separate:
see the [E2E guide](https://github.com/nearai/inference-sdk/blob/main/e2e/README.md).
