"""dstack RTMR3 event-log replay."""

from __future__ import annotations

from pydantic import ValidationError

from ..schemas import DstackEventLogEntrySchema, DstackEventLogSchema
from ..types.attestation_common import AttestationEventLog
from ..types.verification import RuntimeMeasurements
from ..utils.common import sha384, trim_hex_prefix
from ..utils.errors import verification_failure


DSTACK_RUNTIME_EVENT_TYPE = 0x08000001

EVENT_LOG_FIELD_EXPECTATIONS = {
    'digest': 'string',
    'event': 'string',
    'event_payload': 'string',
    'imr': 'unsigned 32-bit integer',
    'event_type': 'unsigned 32-bit integer',
}


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
    for index, entry in enumerate(events):
        if entry.imr != 3:
            continue
        count += 1
        path = f'eventLog[{index}]'
        replayed = sha384(replayed + _event_digest(entry, path))
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


def _parse_event_log(event_log: AttestationEventLog) -> list[DstackEventLogEntrySchema]:
    try:
        if isinstance(event_log, str):
            return DstackEventLogSchema.model_validate_json(event_log).root
        return DstackEventLogSchema.model_validate(event_log).root
    except ValidationError as error:
        raise _invalid_event_log_schema(error) from error


def _invalid_event_log_schema(error: ValidationError):
    issue = error.errors(include_url=False)[0]
    if issue['type'] == 'json_invalid':
        return _invalid_event('eventLog', 'invalid_json', cause=error)

    location = issue['loc']
    path = _event_log_error_path(location)
    expected = _event_log_expected(location)
    return _invalid_event(path, 'invalid_type', expected=expected, cause=error)


def _event_log_error_path(location: tuple[int | str, ...]) -> str:
    return 'eventLog' + ''.join(
        f'[{part}]' if isinstance(part, int) else f'.{part}' for part in location
    )


def _event_log_expected(location: tuple[int | str, ...]) -> str:
    if not location:
        return 'array'
    field = location[-1]
    if isinstance(field, str):
        return EVENT_LOG_FIELD_EXPECTATIONS.get(field, 'valid event log')
    return 'object'


def _event_digest(entry: DstackEventLogEntrySchema, path: str) -> bytes:
    if entry.event_type == DSTACK_RUNTIME_EVENT_TYPE:
        payload = _decode_event_hex(
            entry.event_payload, f'{path}.event_payload', allow_empty=True
        )
        computed = sha384(
            DSTACK_RUNTIME_EVENT_TYPE.to_bytes(4, 'little')
            + b':'
            + entry.event.encode('utf-8')
            + b':'
            + payload
        )
        if entry.digest:
            stored = _decode_event_hex(entry.digest, f'{path}.digest')
            if len(stored) != 48 or stored != computed:
                details: dict[str, object] = {
                    'path': f'{path}.digest',
                    'reason': 'digest_mismatch'
                    if len(stored) == 48
                    else 'wrong_length',
                }
                if len(stored) != 48:
                    details.update({'expectedBytes': 48, 'actualBytes': len(stored)})
                raise verification_failure('measurement.event_log_invalid', details)
        return computed

    digest = _decode_event_hex(entry.digest, f'{path}.digest')
    if len(digest) != 48:
        raise verification_failure(
            'measurement.event_log_invalid',
            {
                'path': f'{path}.digest',
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


def _invalid_event(
    path: str,
    reason: str,
    *,
    expected: str | None = None,
    cause: BaseException | None = None,
):
    details: dict[str, object] = {'path': path, 'reason': reason}
    if expected is not None:
        details['expected'] = expected
    return verification_failure('measurement.event_log_invalid', details, cause=cause)
