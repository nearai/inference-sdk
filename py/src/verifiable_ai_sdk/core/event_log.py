"""dstack RTMR3 event-log replay."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..types.attestation_common import AttestationEventLog
from ..types.verification import RuntimeMeasurements
from ..utils.common import sha384, trim_hex_prefix
from ..utils.errors import verification_failure


DSTACK_RUNTIME_EVENT_TYPE = 0x08000001


@dataclass(frozen=True, kw_only=True)
class EventLogEntry:
    path: str
    digest: str
    event_type: int
    event: str
    event_payload: str
    imr: int


def verify_and_replay_rtmr3(
    event_log: AttestationEventLog, quoted_rtmr3: bytes
) -> RuntimeMeasurements:
    events = _parse_event_log(event_log)
    if len(quoted_rtmr3) != 48:
        raise verification_failure(
            'measurement.rtmr3_mismatch',
            {
                'reason': 'wrong_length',
                'expectedBytes': 48,
                'actualBytes': len(quoted_rtmr3),
            },
        )

    replayed = bytes(48)
    count = 0
    os_image_hash: str | None = None
    compose_hash: str | None = None
    for entry in events:
        if entry.imr != 3:
            continue
        count += 1
        replayed = sha384(replayed + _event_digest(entry))
        if entry.event_type == DSTACK_RUNTIME_EVENT_TYPE:
            if entry.event == 'os-image-hash':
                os_image_hash = entry.event_payload
            elif entry.event == 'compose-hash':
                compose_hash = entry.event_payload

    if count == 0:
        raise verification_failure(
            'measurement.rtmr3_mismatch', {'reason': 'no_events'}
        )
    if replayed != quoted_rtmr3:
        raise verification_failure(
            'measurement.rtmr3_mismatch',
            {'reason': 'replay_mismatch'},
        )
    return RuntimeMeasurements(
        os_image_hash=os_image_hash,
        compose_hash=compose_hash,
    )


def _parse_event_log(event_log: AttestationEventLog) -> list[EventLogEntry]:
    parsed: Any = event_log
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError as error:
            raise verification_failure(
                'measurement.event_log_invalid',
                {'path': 'eventLog', 'reason': 'invalid_json'},
                cause=error,
            ) from error
    if not isinstance(parsed, list):
        raise verification_failure(
            'measurement.event_log_invalid',
            {'path': 'eventLog', 'reason': 'invalid_type', 'expected': 'array'},
        )
    return [_parse_event_log_entry(value, index) for index, value in enumerate(parsed)]


def _parse_event_log_entry(value: object, index: int) -> EventLogEntry:
    path = f'eventLog[{index}]'
    if not isinstance(value, dict):
        raise _invalid_event(path, 'invalid_type', expected='object')
    digest = _required_string(value, 'digest', index)
    event = _optional_string(value, 'event', index) or ''
    event_payload = _optional_string(value, 'event_payload', index) or ''
    imr = value.get('imr')
    if not _is_u32(imr):
        raise _invalid_event(
            f'{path}.imr', 'invalid_type', expected='unsigned 32-bit integer'
        )
    event_type = value.get('event_type', 0)
    if not _is_u32(event_type):
        raise _invalid_event(
            f'{path}.event_type', 'invalid_type', expected='unsigned 32-bit integer'
        )
    return EventLogEntry(
        path=path,
        digest=digest,
        event_type=event_type,
        event=event,
        event_payload=event_payload,
        imr=imr,
    )


def _event_digest(entry: EventLogEntry) -> bytes:
    if entry.event_type == DSTACK_RUNTIME_EVENT_TYPE:
        payload = _decode_event_hex(
            entry.event_payload, f'{entry.path}.event_payload', allow_empty=True
        )
        computed = sha384(
            DSTACK_RUNTIME_EVENT_TYPE.to_bytes(4, 'little')
            + b':'
            + entry.event.encode('utf-8')
            + b':'
            + payload
        )
        if entry.digest:
            stored = _decode_event_hex(entry.digest, f'{entry.path}.digest')
            if len(stored) != 48 or stored != computed:
                details: dict[str, object] = {
                    'path': f'{entry.path}.digest',
                    'reason': 'digest_mismatch'
                    if len(stored) == 48
                    else 'wrong_length',
                }
                if len(stored) != 48:
                    details.update({'expectedBytes': 48, 'actualBytes': len(stored)})
                raise verification_failure('measurement.event_log_invalid', details)
        return computed

    digest = _decode_event_hex(entry.digest, f'{entry.path}.digest')
    if len(digest) != 48:
        raise verification_failure(
            'measurement.event_log_invalid',
            {
                'path': f'{entry.path}.digest',
                'reason': 'wrong_length',
                'expectedBytes': 48,
                'actualBytes': len(digest),
            },
        )
    return digest


def _decode_event_hex(value: str, path: str, *, allow_empty: bool = False) -> bytes:
    normalized = trim_hex_prefix(value)
    if (
        (not allow_empty and not normalized)
        or len(normalized) % 2 != 0
        or any(character not in '0123456789abcdefABCDEF' for character in normalized)
    ):
        raise _invalid_event(path, 'invalid_hex')
    return bytes.fromhex(normalized)


def _required_string(value: dict[object, object], field: str, index: int) -> str:
    field_value = value.get(field)
    if not isinstance(field_value, str):
        raise _invalid_event(
            f'eventLog[{index}].{field}', 'invalid_type', expected='string'
        )
    return field_value


def _optional_string(value: dict[object, object], field: str, index: int) -> str | None:
    if field not in value:
        return None
    field_value = value[field]
    if not isinstance(field_value, str):
        raise _invalid_event(
            f'eventLog[{index}].{field}', 'invalid_type', expected='string'
        )
    return field_value


def _is_u32(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 0xFFFFFFFF
    )


def _invalid_event(path: str, reason: str, *, expected: str | None = None):
    details: dict[str, object] = {'path': path, 'reason': reason}
    if expected is not None:
        details['expected'] = expected
    return verification_failure('measurement.event_log_invalid', details)
