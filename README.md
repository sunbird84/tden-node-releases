# tden-node-releases

Immutable, digest-verified TDEN node release artifacts.

Official candidates are built by GitHub Actions from exact `tden-chain`,
`tden-gateway`, and `tden-deploy` revisions. A candidate remains a workflow
artifact until the multi-node acceptance suite passes. Promotion publishes the
same archive digest; it never rebuilds the package on an operator workstation
or node.

## Release flow

1. Run `Build TDEN node candidate` with exact Chain, Gateway, and Deploy commits.
2. Download that workflow artifact directly on the validation nodes.
3. Complete clean install, join, synchronization, restart, interruption, TLS,
   SSH-hardening, and public-lockdown acceptance.
4. Run `Promote accepted TDEN node candidate` with the candidate run ID and the
   accepted archive SHA-256.

The promotion workflow verifies the successful build workflow, artifact file
set, archive digest, size, source revisions, and candidate description before
publishing the unchanged archive. Configure the `stable-node-release` GitHub
environment with required reviewers so stable publication retains a separate
human approval boundary.

`release-policy.json` pins the bootstrap trust-template and TUF-root digests
accepted by both candidate construction and promotion. Rotating either root is
a separate reviewed policy and client/Console release, not an ordinary node
package update.
