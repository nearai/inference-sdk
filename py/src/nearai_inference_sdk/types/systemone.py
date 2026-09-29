"""Typed System One questions, answers, and explicit receipt verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypedDict

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


@dataclass(frozen=True, kw_only=True)
class SystemOneResult:
    """Unverified output; pass decision_id to client.verify_response()."""

    data: SystemOneResponse
    # X-Generation-Id indexes the signature independently of optional data['id'].
    decision_id: str
