import json

from e2e.helpers import selected_models
from e2e.test_systemone import decision_request


def test_chat_and_systemone_use_their_entries_from_the_shared_catalog(monkeypatch):
    monkeypatch.setenv(
        'NEARAI_E2E_MODELS',
        json.dumps(
            [
                {'id': 'near/chat', 'provider': 'near', 'endpoint': 'chat'},
                {'id': 'typesafe/jev', 'provider': 'external', 'endpoint': 'systemone'},
                {'id': 'external/chat', 'provider': 'external', 'endpoint': 'chat'},
            ]
        ),
    )

    assert selected_models('chat', 'near') == ['near/chat']
    assert selected_models('chat', 'external') == ['external/chat']
    assert decision_request()['model'] == 'typesafe/jev'
