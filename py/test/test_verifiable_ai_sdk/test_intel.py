from verifiable_ai_sdk.utils.intel import _td10_base


def test_td15_quote_uses_its_td10_base_measurements() -> None:
    base = {
        'report_data': [1, 2],
        'mr_config_id': [3, 4],
        'rt_mr3': [5, 6],
        'td_attributes': [0],
    }

    assert _td10_base({'TD15': {'base': base}}) == base
