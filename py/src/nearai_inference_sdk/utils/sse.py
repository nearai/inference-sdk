"""SSE record parsing shared by decryption and completion receipts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Never


@dataclass(frozen=True)
class SseLine:
    content: str
    ending: str


@dataclass(frozen=True)
class SseRecord:
    value: str
    separator: str


@dataclass(frozen=True)
class CompleteSseRecords:
    records: list[SseRecord]
    pending: str


def take_complete_sse_records(value: str, *, eof: bool = False) -> CompleteSseRecords:
    """Split complete events, keeping a trailing CR for the next byte chunk."""

    records: list[SseRecord] = []
    record_start = line_start = index = 0
    while index < len(value):
        if value[index] not in '\r\n':
            index += 1
            continue
        if not eof and value[index] == '\r' and index + 1 == len(value):
            break
        line_end = index
        index += 2 if value[index : index + 2] == '\r\n' else 1
        if line_end == line_start:
            records.append(
                SseRecord(value[record_start:line_start], value[line_start:index])
            )
            record_start = index
        line_start = index
    return CompleteSseRecords(records, value[record_start:])


def split_sse_lines(value: str) -> list[SseLine]:
    lines: list[SseLine] = []
    start = index = 0
    while index < len(value):
        if value[index] not in '\r\n':
            index += 1
            continue
        ending = '\r\n' if value[index : index + 2] == '\r\n' else value[index]
        lines.append(SseLine(value[start:index], ending))
        index += len(ending)
        start = index
    if start < len(value):
        lines.append(SseLine(value[start:], ''))
    return lines


def get_sse_data(line: str) -> str | None:
    if line == 'data':
        return ''
    if not line.startswith('data:'):
        return None
    value = line[len('data:') :]
    return value.removeprefix(' ')


def get_sse_event(record: str) -> str | None:
    """Read the event name, with the last event field taking precedence."""
    event = None
    for line in split_sse_lines(record):
        if line.content == 'event':
            event = ''
        elif line.content.startswith('event:'):
            event = line.content[len('event:') :].removeprefix(' ')
    return event


def get_sse_record_data(record: str) -> str:
    """Join the data fields of one SSE record."""
    return '\n'.join(
        data
        for line in split_sse_lines(record)
        if (data := get_sse_data(line.content)) is not None
    )


def get_sse_data_records(text: str) -> list[str]:
    """Read event payloads from a complete response body."""
    parsed = take_complete_sse_records(text)
    values = [get_sse_record_data(record.value) for record in parsed.records]
    if parsed.pending:
        values.append(get_sse_record_data(parsed.pending))
    return values


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f'Invalid JSON number {value}')


def parse_sse_json(data: str) -> Any:
    return json.loads(data, parse_constant=_reject_json_constant)
