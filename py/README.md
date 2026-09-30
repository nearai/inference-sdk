# NEAR AI Inference SDK for Python

Chat with NEAR AI models using an OpenAI-compatible client. The SDK verifies
deployment attestations before sending a prompt, supports end-to-end encryption
to the model, and can verify the signature of each response.

Use the asynchronous Chat client, connect it to the OpenAI SDK, or use the
verification functions with your own HTTP code.

## Install

```sh
pip install nearai-inference-sdk
```

Requires Python 3.12 or later.

## Quick start

Set your API key, save the code below as `chat.py`, and run `python chat.py`:

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

        # Check the response signature before displaying the answer.
        verified = await client.verify_response(completion.id)
        print(f'Verified {verified.signature_kind} response')
        print(completion.choices[0].message.content or '')


if __name__ == '__main__':
    asyncio.run(main())
```

This example enables E2EE with a model that supports it. Encryption is off by
default. Deployment verification runs with or without encryption, but response
signature verification requires the explicit call shown above.

## What is verified?

- **Gateway:** its Intel TDX attestation, signing identity, measured deployment
  configuration, and TLS identity. The client pins subsequent requests to that
  TLS identity.
- **Model:** every returned model attestation, including deployment measurements
  and NVIDIA GPU evidence when present. Models without supported model
  attestation use Gateway-only verification and cannot use E2EE.
- **Response:** a signature over the exact request and response bytes, checked
  against the verified model or Gateway signer.

The SDK checks that the evidence is authentic. It does not ship an approved
release allowlist; applications can supply their own deployment and image-build
policies. The [guide](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#what-verification-proves)
explains these checks and the different guarantees of model and Gateway signatures.

Successful deployment checks are cached for 60 minutes. Response bytes are kept
separately for 60 minutes after completion, so verify responses before they expire.
Both durations are configurable.

## Documentation

- [Guide](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md) — streaming, OpenAI integration, encryption, policies, and errors.
- [API reference](https://github.com/nearai/inference-sdk/blob/main/py/docs/api-reference.md) — parameters, defaults, and return values.
- [Examples](https://github.com/nearai/inference-sdk/tree/main/examples#python) — runnable client and manual-verification projects.

Direct model endpoints are [experimental](https://github.com/nearai/inference-sdk/blob/main/py/docs/verification-guide.md#direct-model-endpoints).
Use the Gateway client above for production.
