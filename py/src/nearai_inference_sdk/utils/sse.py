"""SSE record parsing shared by decryption and completion receipts."""

from __future__ import annotations

from dataclasses import dataclass


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


def take_complete_sse_records(value: str) -> CompleteSseRecords:
    """Split complete events, keeping a trailing CR for the next byte chunk."""

    records: list[SseRecord] = []
    record_start = line_start = index = 0
    while index < len(value):
        if value[index] not in '\r\n':
            index += 1
            continue
        if value[index] == '\r' and index + 1 == len(value):
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
    return value[1:] if value.startswith(' ') else value


def get_sse_data_records(text: str) -> list[str]:
    """Read complete response data payloads, joining each event's data lines."""

    complete = take_complete_sse_records(text)
    values = [record.value for record in complete.records]
    if complete.pending:
        values.append(complete.pending)
    return [
        '\n'.join(
            data
            for line in split_sse_lines(value)
            if (data := get_sse_data(line.content)) is not None
        )
        for value in values
    ]
