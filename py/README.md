# NEAR AI Inference SDK for Python

`nearai-inference-sdk` provides Chat Completions, Responses, Messages, and System One
with deployment attestation, response signature verification, and optional encryption.

## Install

Python 3.12+. The client uses `asyncio`.

```sh
pip install nearai-inference-sdk
```

## Send and verify a Chat completion

Set `NEARAI_API_KEY`, then send a request with E2EE enabled:

```sh
export NEARAI_API_KEY='your-api-key'
```

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

The client uses the NEAR AI Cloud Gateway by default. It verifies the Gateway and
every returned model report before inference. Call `verify_response(id)` to verify
the response signature; consume streaming responses completely first.

Use the client as an asynchronous context manager, or close it with
`await client.aclose()` when finished.

## Configuration

| Feature | Default |
| --- | --- |
| Gateway and supported model attestation | Enabled |
| Signing algorithm | Ed25519; ECDSA also supported |
| E2EE for supported Chat models | Disabled; enable with `e2ee=True` |
| OHTTP for Chat, Responses, and Messages | Disabled; enable with `ohttp=True`; requires Ed25519 |

Call `await client.verify(model)` to verify a deployment before sending a prompt.
Use deployment and image provenance policies to restrict accepted deployments.
For models without model attestation, use Gateway-only verification with E2EE
disabled and no model attestation policy or deployment checks configured.

## Documentation

- [Verification guide](./docs/verification-guide.md): streaming, official SDK integration,
  encryption, deployment policies, and standalone verification.
- [API reference](./docs/api-reference.md): options, methods, and result fields.
- [Runnable examples](../examples/README.md#python-setup): Gateway and Direct workflows.
- [Development checks](../TESTING.md#validation) and [live E2E tests](../e2e/README.md).
