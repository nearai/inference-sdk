from pydantic import BaseModel


class Context(BaseModel):
    api_domain: str
    api_url: str
    api_key: str
    model: str


class ChatCompletionsResponse(BaseModel):
    id: str
    request_body_raw: bytes
    response_body_raw: bytes
