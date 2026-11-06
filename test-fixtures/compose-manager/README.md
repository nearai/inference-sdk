# Compose Manager action-log fixture

Synthetic deployment data for SDK tests. `actions_hash`
is SHA-256 of compact UTF-8 JSON with each action's keys sorted alphabetically,
as defined by `nearai/compose-manager`. `file_sha256` hashes the exact `compose`
string, including its final newline. The `release-unicode-é-€-🌍` tag exercises
2-, 3-, and 4-byte UTF-8 sequences; it and the `services` array exercise lossless
canonicalization. Recompute `actions_hash` after changing any action value.

The fixture uses the existing published launcher bundle to test image proof
verification offline. It is not a production model deployment or a real TDX quote.
