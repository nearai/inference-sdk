"""Convert TypeSafe image uploads to the JSON sent through OpenRouter."""

import base64
import json
import re
from email import policy
from email.errors import MessageError
from email.parser import BytesParser

import httpx

from ..utils.errors import ApiError, api_failure


def normalize_systemone_request(
    body: bytes, headers: httpx.Headers
) -> tuple[bytes, object]:
    """Keep ordinary JSON verbatim; capture converted images before verification."""
    multipart = (
        headers.get('content-type', '').split(';')[0].strip().lower()
        == 'multipart/form-data'
    )
    files: dict[str, bytes] = {}
    json_body = body
    if multipart:
        try:
            message = BytesParser(
                policy=policy.default.clone(raise_on_defect=True)
            ).parsebytes(
                b'Content-Type: '
                + headers['content-type'].encode('ascii')
                + b'\r\n\r\n'
                + body
            )
            if not message.is_multipart():
                raise _invalid_assets('a valid multipart System One request')
            names: set[str] = set()
            for part in message.iter_parts():
                name = part.get_param('name', header='content-disposition')
                content = part.get_payload(decode=True)
                if (
                    not isinstance(name, str)
                    or not name
                    or name in names
                    or (not names and name != 'request')
                    or not isinstance(content, bytes)
                ):
                    raise _invalid_assets('unique multipart names, with request first')
                names.add(name)
                if name == 'request':
                    json_body = content
                else:
                    content_type = (
                        part.get_content_type() if 'content-type' in part else ''
                    )
                    if content_type not in (
                        '',
                        'application/octet-stream',
                        'image/png',
                        'image/jpeg',
                        'image/jpg',
                    ):
                        raise _invalid_assets('PNG or JPEG image file parts')
                    files[name] = content
            if 'request' not in names:
                raise _invalid_assets('a multipart request JSON part')
        except (MessageError, ValueError):
            raise _invalid_assets('a valid multipart System One request') from None
    try:
        parsed = json.loads(json_body)
    except ValueError:
        raise _invalid_assets(
            'a JSON System One request with a non-empty model'
        ) from None
    has_assets = isinstance(parsed, dict) and parsed.get('assets') is not None
    if has_assets:
        assets = parsed['assets']
        if not isinstance(assets, dict):
            raise _invalid_assets('an image assets map')
        images = {}
        for reference, asset in assets.items():
            if (
                not reference.strip()
                or not isinstance(asset, dict)
                or asset.get('type', 'image') != 'image'
            ):
                raise _invalid_assets('named image assets')
            if asset.get('part') is not None:
                part_name = asset['part']
                if not isinstance(part_name, str) or part_name not in files:
                    raise _invalid_assets('one existing file part per image asset')
                data = files.pop(part_name)
            else:
                if asset.get('format') not in ('png', 'jpg', 'jpeg') or not isinstance(
                    asset.get('data_base64'), str
                ):
                    raise _invalid_assets(
                        'PNG or JPEG assets with standard base64 data'
                    )
                try:
                    data = base64.b64decode(asset['data_base64'], validate=True)
                except ValueError:
                    raise _invalid_assets(
                        'PNG or JPEG assets with standard base64 data'
                    ) from None
            # Decode and validate dimensions upstream. Only the MIME type is
            # needed here, including when the SDK sends application/octet-stream.
            mime = _image_mime(data)
            images[reference] = {
                'type': 'image_url',
                'image_url': {
                    'url': f'data:{mime};base64,{base64.b64encode(data).decode("ascii")}'
                },
            }
        used: set[str] = set()
        references = sorted(images, key=len, reverse=True)
        pattern = (
            re.compile('|'.join(re.escape(ref) for ref in references))
            if references
            else None
        )

        def replace(value):
            if isinstance(value, str):
                if value in images:
                    used.add(value)
                    return images[value]
                if pattern is None:
                    return value
                parts = []
                end = 0
                for match in pattern.finditer(value):
                    if match.start() > end:
                        parts.append(value[end : match.start()])
                    reference = match.group()
                    parts.append(images[reference])
                    used.add(reference)
                    end = match.end()
                if not parts:
                    return value
                if end < len(value):
                    parts.append(value[end:])
                return parts
            if isinstance(value, list):
                return [replace(item) for item in value]
            if isinstance(value, dict):
                return {key: replace(item) for key, item in value.items()}
            return value

        if 'state' in parsed:
            parsed['state'] = replace(parsed['state'])
        if isinstance(parsed.get('questions'), dict):
            for question in parsed['questions'].values():
                if isinstance(question, dict):
                    for field in ('instructions', 'criteria'):
                        if field in question:
                            question[field] = replace(question[field])
        if len(used) != len(images):
            raise _invalid_assets(
                'every image referenced in state, instructions, or criteria'
            )
        del parsed['assets']
    if files:
        raise _invalid_assets('one image asset per file part')
    if not multipart and not has_assets:
        return body, parsed
    for name in (
        'content-length',
        'content-encoding',
        'transfer-encoding',
        'trailer',
        'content-md5',
        'digest',
        'content-digest',
        'repr-digest',
    ):
        headers.pop(name, None)
    headers['content-type'] = 'application/json'
    return json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode(), parsed


def _image_mime(data: bytes) -> str:
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if data.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    raise _invalid_assets('PNG or JPEG image bytes')


def _invalid_assets(expected: str) -> ApiError:
    return api_failure(
        'api.invalid_input',
        {'field': 'systemone', 'reason': 'unsupported_value', 'expected': expected},
    )
