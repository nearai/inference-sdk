from typing import TypedDict


class Context(TypedDict):
    api_domain: str
    api_url: str
    api_key: str
    model: str


class ChatCompletionsParams(TypedDict):
    api_url: str
    api_key: str
    request_body: dict


class ChatCompletionsResponse(TypedDict):
    id: str
    request_body_raw: bytes
    response_body_raw: bytes
