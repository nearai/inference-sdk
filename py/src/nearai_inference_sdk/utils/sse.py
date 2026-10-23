"""SSE record parsing shared by decryption and completion receipts."""

from __future__ import annotations

from collections.abc import Iterator
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


class SseDecoder:
    """Scan each incoming byte once, retaining an unfinished event between chunks."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._index = 0
        self._line_start = 0

    def feed(self, chunk: bytes) -> Iterator[SseRecord]:
        self._buffer.extend(chunk)
        record_start = 0
        index, line_start = self._index, self._line_start
        while index < len(self._buffer):
            if self._buffer[index] not in (10, 13):
                index += 1
                continue
            # The next chunk determines whether a trailing CR belongs to CRLF.
            if self._buffer[index] == 13 and index + 1 == len(self._buffer):
                break
            line_end = index
            index += 2 if self._buffer[index : index + 2] == b'\r\n' else 1
            if line_end == line_start:
                yield SseRecord(
                    self._buffer[record_start:line_start].decode(),
                    self._buffer[line_start:index].decode(),
                )
                record_start = index
            line_start = index
        if record_start:
            del self._buffer[:record_start]
        self._index, self._line_start = index - record_start, line_start - record_start

    def finish(self) -> str:
        pending = self._buffer.decode()
        self._buffer.clear()
        self._index = self._line_start = 0
        return pending


def take_complete_sse_records(value: str) -> CompleteSseRecords:
    decoder = SseDecoder()
    return CompleteSseRecords(list(decoder.feed(value.encode())), decoder.finish())


def iter_sse_lines(value: str) -> Iterator[SseLine]:
    start = index = 0
    while index < len(value):
        if value[index] not in '\r\n':
            index += 1
            continue
        ending = '\r\n' if value[index : index + 2] == '\r\n' else value[index]
        yield SseLine(value[start:index], ending)
        index += len(ending)
        start = index
    if start < len(value):
        yield SseLine(value[start:], '')


def get_sse_data(line: str) -> str | None:
    if line == 'data':
        return ''
    if not line.startswith('data:'):
        return None
    value = line[len('data:') :]
    return value.removeprefix(' ')


def get_sse_record_data(record: str) -> str:
    data = bytearray()
    for line in iter_sse_lines(record):
        value = get_sse_data(line.content)
        if value is not None:
            data.extend(value.encode())
            data.append(10)
    if data:
        data.pop()
    return data.decode()


def get_sse_data_records(text: str) -> list[str]:
    """Read complete response data payloads, joining each event's data lines."""

    complete = take_complete_sse_records(text)
    values = [record.value for record in complete.records]
    if complete.pending:
        values.append(complete.pending)
    return [get_sse_record_data(value) for value in values]
