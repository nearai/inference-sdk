from dataclasses import replace

import pytest

from nearai_inference_sdk import (
    DirectClientBinding,
    DirectModelAttestation,
    FetchedDirectModelAttestations,
    ModelAttestationVerifiers,
    VerificationError,
    verify_direct_model_attestations,
)

from .fixtures import (
    NONCE,
    TLS_FINGERPRINT,
    create_model_attestation,
    create_model_quote,
    create_gateway_tls_quote,
)


def direct_report(**overrides):
    return replace(
        DirectModelAttestation(
            **vars(create_model_attestation()), model_name='test-model'
        ),
        **overrides,
    )


@pytest.mark.parametrize('tls', [False, True])
async def test_all_direct_reports_are_verified_and_only_serving_report_matches_peer(
    tls,
):
    root = direct_report(spki_fingerprint=TLS_FINGERPRINT if tls else None)
    sibling = replace(
        root, intel_quote='bb', spki_fingerprint='44' * 32 if tls else None
    )
    quotes = {
        'aa': create_gateway_tls_quote() if tls else create_model_quote(),
        'bb': create_gateway_tls_quote(tls_fingerprint='44' * 32)
        if tls
        else create_model_quote(),
    }
    checked = []

    def verify_quote(value):
        checked.append(value)
        return quotes[value]

    fetched = FetchedDirectModelAttestations(
        serving_attestation=replace(root),
        attestations=(sibling, root),
        client_binding=DirectClientBinding(
            nonce=NONCE, spki_fingerprint=TLS_FINGERPRINT if tls else None
        ),
    )
    verified = await verify_direct_model_attestations(
        fetched, verifiers=ModelAttestationVerifiers(tdx_quote=verify_quote)
    )
    assert checked == ['bb', 'aa']
    assert verified.serving_attestation == verified.attestations[1]
    assert verified.tls_binding.kind == ('attested' if tls else 'none')
    assert verified.spki_fingerprints == (('44' * 32, TLS_FINGERPRINT) if tls else ())


@pytest.mark.parametrize(
    'fault', ['sibling_quote', 'sibling_tls', 'peer', 'serving_missing']
)
async def test_invalid_direct_report_set_or_peer_fails_verification(fault):
    root = direct_report(spki_fingerprint=TLS_FINGERPRINT)
    sibling = replace(root, intel_quote='bb')
    quotes = {'aa': create_gateway_tls_quote(), 'bb': create_gateway_tls_quote()}
    if fault == 'sibling_quote':
        quotes['bb'] = replace(quotes['bb'], debug_enabled=True)
    if fault == 'sibling_tls':
        sibling = replace(sibling, spki_fingerprint='55' * 32)
    fetched = FetchedDirectModelAttestations(
        serving_attestation=replace(root, intel_quote='cc')
        if fault == 'serving_missing'
        else root,
        attestations=(root, sibling),
        client_binding=DirectClientBinding(
            nonce=NONCE,
            spki_fingerprint='55' * 32 if fault == 'peer' else TLS_FINGERPRINT,
        ),
    )
    with pytest.raises(VerificationError) as raised:
        await verify_direct_model_attestations(
            fetched, verifiers=ModelAttestationVerifiers(tdx_quote=quotes.__getitem__)
        )
    assert (
        raised.value.failure.code
        == {
            'sibling_quote': 'policy.debug_enabled',
            'sibling_tls': 'binding.report_data_mismatch',
            'peer': 'binding.spki_fingerprint_mismatch',
            'serving_missing': 'input.invalid',
        }[fault]
    )
