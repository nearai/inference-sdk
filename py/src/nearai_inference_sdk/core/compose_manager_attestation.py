"""Authenticate Compose Manager actions without claiming successful execution."""

import json

from ..types.compose_manager import (
    ComposeManagerAttestation,
    VerifiedComposeManagerAttestation,
)
from ..types.verification import AttestationPolicy, TdxQuoteVerifier
from ..utils.common import require_byte_length, sha256
from ..utils.errors import verification_failure
from .attestation_common import (
    _verify_quote_report_data_length_and_nonce,
    verify_advertised_report_data,
    verify_app_compose_mrconfig_binding,
    verify_reported_nonce,
)
from .dstack_attestation import verify_tdx_quote
from .event_log import verify_and_replay_rtmr3


async def verify_compose_manager_attestation(
    attestation: ComposeManagerAttestation,
    app_compose: str,
    nonce: str,
    policy: AttestationPolicy | None = None,
    tdx_quote_verifier: TdxQuoteVerifier | None = None,
) -> VerifiedComposeManagerAttestation:
    verify_reported_nonce(attestation.nonce, nonce, 'composeManagerAttestation')
    quote = await verify_tdx_quote(attestation.intel_quote, policy, tdx_quote_verifier)
    verify_advertised_report_data(attestation.reported_quote_data, quote.report_data)
    _verify_quote_report_data_length_and_nonce(quote.report_data, nonce)
    actions_json = json.dumps(
        attestation.actions, sort_keys=True, separators=(',', ':'), ensure_ascii=False
    )
    actions_hash = sha256(actions_json.encode('utf-8'))
    reported_hash = require_byte_length(
        attestation.actions_hash, 32, 'compose_manager_attestation.actions_hash'
    )
    if actions_hash != reported_hash or quote.report_data[:32] != actions_hash:
        raise verification_failure('binding.compose_manager_actions_mismatch')
    verify_app_compose_mrconfig_binding(app_compose, quote.mr_config_id)
    measurements = verify_and_replay_rtmr3(attestation.event_log, quote.rt_mr3)
    return VerifiedComposeManagerAttestation(
        actions=attestation.actions,
        tcb_status=quote.tcb_status,
        advisory_ids=tuple(quote.advisory_ids),
        runtime_measurements=measurements,
    )
