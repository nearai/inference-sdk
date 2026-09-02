import asyncio
import json
import os

import aiohttp
from verifiable_ai_sdk import (
    AttestationClient,
    find_model_attestation_for_signature,
    verify_gateway_attestation,
    verify_gateway_response,
    verify_model_attestation,
    verify_model_response,
)


API_URL = "https://cloud-api.near.ai/v1/chat/completions"
MODEL = "z-ai/glm-5.2"


async def fetch_completion(
    session: aiohttp.ClientSession, api_key: str, stream: bool
) -> tuple[bytes, bytes, str]:
    request_body = json.dumps(
        {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Reply with the word ok."}],
            "stream": stream,
            "max_tokens": 8,
        },
        separators=(",", ":"),
    ).encode()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
        "x-no-aliasing": "true",
    }
    async with session.post(API_URL, data=request_body, headers=headers) as response:
        response_body = await response.read()
        if not response.ok:
            raise RuntimeError(
                f"Completion request failed ({response.status}): "
                f"{response_body.decode(errors='replace')}"
            )

    # Keep these original bytes unchanged for response-signature verification.
    return request_body, response_body, read_completion_id(response_body, stream)


def read_completion_id(response_body: bytes, stream: bool) -> str:
    if not stream:
        completion = json.loads(response_body)
        completion_id = completion.get("id") if isinstance(completion, dict) else None
        if isinstance(completion_id, str):
            return completion_id
        raise RuntimeError("Completion response did not contain an id")

    for line in response_body.decode().splitlines():
        if not line.startswith("data: ") or line == "data: [DONE]":
            continue
        try:
            event = json.loads(line.removeprefix("data: "))
        except json.JSONDecodeError:
            continue
        completion_id = event.get("id") if isinstance(event, dict) else None
        if isinstance(completion_id, str):
            return completion_id
    raise RuntimeError("Streaming completion response did not contain an id")


async def verify_completion(
    client: AttestationClient,
    session: aiohttp.ClientSession,
    api_key: str,
    stream: bool,
) -> None:
    request_body, response_body, completion_id = await fetch_completion(
        session, api_key, stream
    )
    signature = await client.fetch_completion_signature(completion_id)
    label = "Streaming" if stream else "Non-streaming"

    if signature.kind == "provider_tee":
        fetched = await client.fetch_model_attestations(MODEL)
        attestation = find_model_attestation_for_signature(
            fetched.attestations, signature
        )
        verified_attestation = await verify_model_attestation(
            attestation, fetched.client_binding
        )
        verify_model_response(
            request_body, response_body, signature, verified_attestation
        )
        print(f"{label}: verified a model-serving TEE signature.")
        return

    fetched = await client.fetch_gateway_attestation(
        signing_algo=signature.signer.signing_algo
    )
    verified_attestation = await verify_gateway_attestation(
        fetched.attestation, fetched.client_binding
    )
    verify_gateway_response(
        request_body, response_body, signature, verified_attestation
    )
    print(f"{label}: verified a Gateway signature.")


async def main() -> None:
    api_key = os.environ.get("NEARAI_API_KEY")
    if not api_key:
        raise RuntimeError("NEARAI_API_KEY is required")

    client = AttestationClient(api_key)
    async with aiohttp.ClientSession(auto_decompress=False) as session:
        await verify_completion(client, session, api_key, stream=False)
        await verify_completion(client, session, api_key, stream=True)


if __name__ == "__main__":
    asyncio.run(main())
