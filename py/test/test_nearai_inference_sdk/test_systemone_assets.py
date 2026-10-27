"""Image conversion preserves content placement and rejects lost uploads."""

import base64
import json
from pathlib import Path

import httpx
import pytest

from nearai_inference_sdk import ApiError
from nearai_inference_sdk.core.systemone_assets import normalize_systemone_request

PNG = (
    Path(__file__).resolve().parents[3] / 'test-fixtures/systemone/rectangle.png'
).read_bytes()
ASSET = {'format': 'png', 'data_base64': base64.b64encode(PNG).decode()}
PART = {
    'type': 'image_url',
    'image_url': {'url': 'data:image/png;base64,' + ASSET['data_base64']},
}


def test_base64_assets_expand_content_values_keep_keys_and_other_fields():
    headers = httpx.Headers({'content-type': 'application/json', 'digest': 'old-body'})
    request = {
        'model': 'a+b',
        'state': {'a+b': ['a+b', 'before a+b and a+b after']},
        'questions': {
            'a+b': {
                'type': 'noul',
                'instructions': {'nested': 'a+b'},
                'criteria': {'true': 'a+b', 'false': None},
                'future': 'a+b',
            },
            'choice': {
                'type': 'choice',
                'instructions': 'Pick',
                'criteria': {'a+b': 'a+b'},
            },
            'score': {
                'type': 'score',
                'instructions': 'Rate',
                'criteria': ['a+b', None],
            },
        },
        'assets': {'a+b': ASSET},
        'metadata': 'a+b',
    }
    body, _ = normalize_systemone_request(json.dumps(request).encode(), headers)
    assert json.loads(body) == {
        'model': 'a+b',
        'state': {'a+b': [PART, ['before ', PART, ' and ', PART, ' after']]},
        'questions': {
            'a+b': {
                'type': 'noul',
                'instructions': {'nested': PART},
                'criteria': {'true': PART, 'false': None},
                'future': 'a+b',
            },
            'choice': {
                'type': 'choice',
                'instructions': 'Pick',
                'criteria': {'a+b': PART},
            },
            'score': {
                'type': 'score',
                'instructions': 'Rate',
                'criteria': [PART, None],
            },
        },
        'metadata': 'a+b',
    }
    assert 'digest' not in headers


def multipart(request, files):
    http = httpx.Request(
        'POST',
        'https://gateway.test/v1/systemone',
        files=[
            (
                'request',
                ('request.json', json.dumps(request).encode(), 'application/json'),
            ),
            *files,
        ],
    )
    return normalize_systemone_request(http.read(), http.headers)


def test_multipart_prefers_file_bytes_detects_jpeg_without_mime_type():
    _, parsed = multipart(
        {
            'state': 'photo',
            'assets': {'photo': {'part': 'upload', 'data_base64': 'ignored'}},
        },
        [
            ('upload', ('upload', b'\xff\xd8\xff\xe0', 'application/octet-stream')),
        ],
    )
    assert parsed == {
        'state': {
            'type': 'image_url',
            'image_url': {'url': 'data:image/jpeg;base64,/9j/4A=='},
        }
    }


@pytest.mark.parametrize(
    'payload',
    [
        {'state': 'photo', 'assets': {'photo': {**ASSET, 'data_base64': '!!!'}}},
        {
            'state': 'photo',
            'assets': {'photo': {'format': 'png', 'data_base64': 'bm90LWltYWdl'}},
        },
        {'state': 'text', 'assets': {'photo': ASSET}},
        {'state': 'photo', 'assets': {'photo': {'part': 'missing'}}},
    ],
)
def test_rejects_assets_that_cannot_be_faithfully_converted(payload):
    with pytest.raises(ApiError, match='api.invalid_input'):
        normalize_systemone_request(
            json.dumps(payload).encode(),
            httpx.Headers({'content-type': 'application/json'}),
        )


@pytest.mark.parametrize('fault', ['duplicate', 'unused', 'shared'])
def test_rejects_duplicate_unused_and_shared_multipart_parts(fault):
    assets = {'photo': {'part': 'upload'}}
    files = [('upload', ('upload', PNG, 'image/png'))]
    if fault == 'shared':
        assets['other'] = {'part': 'upload'}
    else:
        files.append(
            (
                'upload' if fault == 'duplicate' else 'unused',
                ('upload', PNG, 'image/png'),
            )
        )
    with pytest.raises(ApiError, match='api.invalid_input'):
        multipart({'state': ['photo', 'other'], 'assets': assets}, files)
