"""Typed System One questions, answers, and explicit receipt verification."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Literal, NotRequired, TypedDict

from ..utils.errors import ApiError
from .inference_client import VerifiedCompletionResult


SystemOneContent = str | dict[str, Any] | list[Any]


class SystemOneNoulCriteria(TypedDict, total=False):
    true: SystemOneContent
    false: SystemOneContent


class SystemOneNoulQuestion(TypedDict):
    type: Literal['noul']
    instructions: NotRequired[SystemOneContent]
    criteria: NotRequired[SystemOneNoulCriteria]


class SystemOneChoiceQuestion(TypedDict):
    type: Literal['choice']
    instructions: NotRequired[SystemOneContent]
    criteria: dict[str, SystemOneContent | None]


class SystemOneScoreQuestion(TypedDict):
    type: Literal['score']
    instructions: NotRequired[SystemOneContent]
    criteria: list[SystemOneContent]


SystemOneQuestion = (
    SystemOneNoulQuestion | SystemOneChoiceQuestion | SystemOneScoreQuestion
)


class SystemOneRequest(TypedDict):
    model: str
    state: SystemOneContent
    questions: dict[str, SystemOneQuestion]


class SystemOneNoulAnswer(TypedDict):
    type: Literal['noul']
    noul: float


class SystemOneChoiceAnswer(TypedDict):
    type: Literal['choice']
    choice: str
    confidence: float
    probabilities: dict[str, float]


class SystemOneScoreAnswer(TypedDict):
    type: Literal['score']
    score: float
    confidence: float
    probabilities: dict[str, float]
    legend: dict[str, SystemOneContent]


SystemOneAnswer = SystemOneNoulAnswer | SystemOneChoiceAnswer | SystemOneScoreAnswer


class SystemOneUsage(TypedDict):
    input_tokens: int
    output_tokens: int


class SystemOneResponse(TypedDict):
    id: NotRequired[str | None]
    model: str
    answers: dict[str, SystemOneAnswer]
    usage: SystemOneUsage


@dataclass(kw_only=True)
class SystemOneResult:
    """Output is unverified until verify() succeeds over the captured wire bytes."""

    data: SystemOneResponse
    signature_id: str
    _verify: Callable[[], Coroutine[Any, Any, VerifiedCompletionResult]] = field(
        repr=False
    )
    _verification: asyncio.Task[VerifiedCompletionResult] | None = field(
        default=None, init=False, repr=False
    )

    async def verify(self) -> VerifiedCompletionResult:
        if self._verification is None:
            self._verification = asyncio.create_task(self._verify())
            self._verification.add_done_callback(_observe_verification)
        task = self._verification
        try:
            return await asyncio.shield(task)
        except ApiError as error:
            if (
                error.retryable
                or error.failure.code == 'api.completion_signature_unavailable'
            ) and self._verification is task:
                self._verification = None
            raise


def _observe_verification(task: asyncio.Task[VerifiedCompletionResult]) -> None:
    if not task.cancelled():
        task.exception()
