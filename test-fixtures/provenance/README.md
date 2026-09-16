# Image provenance fixture

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
