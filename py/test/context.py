import os

from .types import Context


def init_context() -> Context:
    api_domain = os.getenv('API_DOMAIN')
    if not api_domain:
        raise ValueError('Missing env API_DOMAIN')

    api_key = os.getenv('API_KEY')
    if not api_key:
        raise ValueError('Missing env API_KEY')

    model = os.getenv('MODEL')
    if not model:
        raise ValueError('Missing env MODEL')

    return {
        'api_domain': api_domain,
        'api_url': f'https://{api_domain}/v1',
        'api_key': api_key,
        'model': model,
    }

