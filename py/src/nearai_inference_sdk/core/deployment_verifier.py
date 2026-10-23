"""Run caller-owned policy on authenticated deployment evidence."""

from typing import Literal

from ..types.verification import DeploymentVerifier, MeasuredDeployment
from ..utils.common import maybe_await
from ..utils.errors import VerificationError, verification_failure


async def run_deployment_verifier(
    deployment: MeasuredDeployment,
    verifier: DeploymentVerifier | None,
) -> Literal['not_checked', 'verified']:
    if verifier is None:
        return 'not_checked'
    try:
        await maybe_await(verifier(deployment))
    except VerificationError:
        raise
    except Exception as error:
        raise verification_failure(
            'provenance.verification_failed', cause=error
        ) from error
    return 'verified'
