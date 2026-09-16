# Image provenance fixtures

`compose-manager-launcher.bundle.json` is a public GitHub artifact attestation
downloaded from the API recorded in `source.json`. It contains a public signing
certificate, transparency-log evidence and an in-toto statement; no private keys
or authentication tokens are included.

`trusted-root.json` is the Sigstore production trust root fetched and
authenticated through the official TUF trust chain on 2026-09-16. It is a test
snapshot only; SDK verification uses the library's current production trust root.

All three SDKs use this fixture to test signature verification and rejection of
tampered or mismatched evidence. The certificate is intentionally verified at its
attested signing time, not against its current expiration date.

## Cross-repository reusable workflow

`reusable-workflow.bundle.json` is GitHub CLI's public reusable-workflow
attestation fixture, copied without changing its signed content from
[this immutable source](https://github.com/cli/cli/blob/8d0518645f309d5ceec8eab9663299e4b75f33b4/pkg/cmd/attestation/test/data/reusable-workflow-attestation.sigstore.json).
Its source URL and identities are recorded in `reusable-workflow-source.json`.

The attested artifact is a wheel with SHA-256
`49a3aa6075e0f49f82843e74b5baa614ad2a588e6675612bf108a0a008c5ac25`.
The caller is `malancas/attest-demo/.github/workflows/shared.yml@refs/heads/main`,
while the certificate's signer is the reusable workflow
`github/artifact-attestations-workflows/.github/workflows/attest.yml`, pinned to
commit `09b495c3f12c7881b3cc17209a327792065c1a1d`.

The SLSA workflow fields and certificate source-repository extensions identify
the caller. The certificate SAN and build-signer extensions identify the called
workflow. The bundle uses SLSA v1, Sigstore bundle v0.3 and Rekor `dsse/0.0.1`.
Its real certificate, signature and log evidence verify against the existing
`trusted-root.json`; no replacement trust root is required.
