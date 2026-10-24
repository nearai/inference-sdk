import pytest

from nearai_inference_sdk.utils.sse import SseDecoder, SseRecord


@pytest.mark.parametrize('chunk_size', [1, 3, 1024])
def test_sse_decoder_preserves_fragmented_events_and_unfinished_tail(chunk_size):
    long_record = 'data: ' + '回答' * 4096 + '\r\n'
    wire = (
        ': keepalive\r\r' + long_record + '\r\ndata: [DONE]\n\ndata: tail\r'
    ).encode()
    decoder = SseDecoder()
    records = []
    for offset in range(0, len(wire), chunk_size):
        records.extend(decoder.feed(wire[offset : offset + chunk_size]))
    assert records == [
        SseRecord(': keepalive\r', '\r'),
        SseRecord(long_record, '\r\n'),
        SseRecord('data: [DONE]\n', '\n'),
    ]
    assert decoder.finish() == 'data: tail\r'


def test_sse_decoder_parses_records_as_they_are_consumed():
    decoder = SseDecoder()
    records = iter(decoder.feed(b'data: first\n\ndata: \xff\n\n'))
    assert next(records) == SseRecord('data: first\n', '\n')
    with pytest.raises(UnicodeDecodeError):
        next(records)
