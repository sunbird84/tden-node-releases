# Shared protocol fixtures for frozen source tests

These four files are byte-for-byte snapshots of the existing shared test inputs used by the pinned Chain and Gateway source tests. The build workflow stages them at the sibling paths those tests already read. It runs the original complete source test commands without changing the production source commits or the tests.

The original local tden-spec working tree has uncommitted files. The manifest records file hashes and lengths, not an unsupported claim that these bytes belong to its HEAD commit. This release-control commit binds the complete fixture contents and staging code for the GitHub build provenance.

All four files contain synthetic protocol examples, public keys and test signatures. They contain no private keys or production credentials. Passing these tests does not establish real user presence, authority or judicial acceptance, consent, payment, deployment acceptance or node readiness.

The loader checks the exact four-file set, JSON encoding, byte lengths and SHA-256 digests before copying into a new destination. It refuses an existing destination and does not change the three frozen source repositories.
