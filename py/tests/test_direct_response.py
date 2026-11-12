from dataclasses import replace

import pytest

from nearai_inference_sdk import (
    CompletionSignatureReference,
    DirectModelAttestation,
    MeasuredDeployment,
    RuntimeMeasurements,
    SigningIdentity,
    VerificationError,
    VerifiedDirectModelAttestation,
    find_direct_model_attestations_for_signature,
)

from .support.attestation import create_model_attestation


@pytest.mark.parametrize('signing_algo', ['ed25519', 'ecdsa'])
def test_selects_the_complete_direct_signer_group(signing_algo):
    length = 32 if signing_algo == 'ed25519' else 20
    signer = SigningIdentity(signing_algo=signing_algo, signing_address='ab' * length)
    first = VerifiedDirectModelAttestation(
        report=DirectModelAttestation(
            **vars(create_model_attestation(signer=signer)), model_name='test-model'
        ),
        signer=signer,
        tcb_status='UpToDate',
        advisory_ids=(),
        deployment=MeasuredDeployment(
            app_compose='{}', runtime_measurements=RuntimeMeasurements()
        ),
        deployment_provenance='not_checked',
        gpu_evidence='not_provided',
        model_name='test-model',
        instance_id='first',
        spki_fingerprint='11' * 32,
    )
    second = replace(
        first,
        signer=replace(signer, signing_address='0X' + 'AB' * length),
        instance_id='second',
        spki_fingerprint='22' * 32,
    )
    other = replace(first, signer=replace(signer, signing_address='cd' * length))
    signature = CompletionSignatureReference(kind='provider_tee', signer=signer)
    attestations = (other, first, second)
    assert find_direct_model_attestations_for_signature(attestations, signature) == (
        first,
        second,
    )

    for candidates, reference, code in (
        ((other,), signature, 'signature.signer_mismatch'),
        (attestations, replace(signature, kind='gateway'), 'signature.kind_mismatch'),
        (
            attestations,
            replace(
                signature,
                signer=replace(
                    signer,
                    signing_algo='ecdsa' if signing_algo == 'ed25519' else 'ed25519',
                ),
            ),
            'signature.signer_mismatch',
        ),
    ):
        with pytest.raises(VerificationError) as raised:
            find_direct_model_attestations_for_signature(candidates, reference)
        assert raised.value.failure.code == code
