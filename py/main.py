import asyncio

import requests

from verification_sdk import verify_gateway_attestation, AttestationReport, GatewayAttestation


res = requests.get("https://cloud-api.near.ai/v1/attestation/report")
report = AttestationReport.model_validate_json(res.text)

promise = verify_gateway_attestation(report.gateway_attestation, 'cloud-api.near.ai')
asyncio.run(promise)

