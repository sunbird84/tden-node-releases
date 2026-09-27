# Stable deployment acceptance gate (WP-06)

Status: fail-closed. `acceptance-policy.json` has `trusted_source: null` because
this repository currently has no reviewed deployment acceptance producer. This
document specifies a future integration contract; it does not claim that any
deployment test, acceptance workflow, or live attestation already exists.

## Trust boundary

The publish workflow first verifies the original candidate archive and its
GitHub build provenance. Stable additionally requires a runtime candidate whose
build description has its own verified attestation; legacy candidates without
that source/profile binding remain preview-only. For `stable` only,
`scripts/acceptance_gate.py` then
fetches an acceptance run and its fixed-name `node-deployment-acceptance`
artifact directly from GitHub. The operator supplies only a run ID. No JSON
file or PASS flag can be supplied through `workflow_dispatch`. A stable release
cannot be created, or an existing preview edited, until this gate succeeds.
Preview publication remains available for controlled testing.
Before stable publication, the workflow also rejects a different candidate
already released under the same normalized node version. New package bytes
require a new version/candidate number; stable operations are serialized while
preview remains independently available.

The trusted source must be a reviewed workflow **in this release repository**
and pinned by exact 40-character commit and workflow path in
`acceptance-policy.json`. The gate requires a successful `workflow_dispatch`
run at that commit, its exact run attempt, successful independent `accept-ID`
jobs, and a GitHub-hosted SLSA attestation of `acceptance-manifest.json` from
that same run, attempt, workflow and commit. The publish job executes
`gh attestation verify` before parsing its verified receipt. The attestation
proves the manifest's origin and bytes, not the truth of its test claims: the
pinned producer must actually execute/observe the tests and generate the
manifest from their results, not attest an operator-provided report.

`stable-node-release` environment reviewers remain a separate boundary, not a
substitute for machine evidence. This gate does not authorize TUF or DAO
promotion and does not change any release asset bytes.

## Acceptance artifact contract

The artifact must contain exactly `acceptance-manifest.json` and the evidence
files it names under `evidence/<test_id>/`. JSON uses unique keys. The manifest
has exactly these fields:

| Field | Required meaning |
| --- | --- |
| `protocol` | `tden:node-deployment-acceptance:v1` |
| `archive_sha256` | SHA-256 of the original, attested candidate tar.gz |
| `candidate_run_id`, `candidate_run_attempt` | Exact verified build run/attempt |
| `candidate_build_sha256` | SHA-256 of the attested `candidate-build.json` |
| `source_commits` | Exact `chain_commit`, `gateway_commit`, `deploy_commit` map |
| `runtime_bundle` | Exact attested candidate runtime manifest/profile/helper binding |
| `network_id`, `environment` | Nonempty test-network and isolated environment identifiers |
| `promotable`, `unresolved_blockers` | Must be `true` and `[]`; derived packages and open blockers fail |
| `started_at_utc`, `finished_at_utc` | UTC timestamps after build and within the trusted run; no more than 30 days old |
| `results` | One entry per required test ID, with no missing, duplicate or extra IDs |

Each result has exactly `test_id`, `status`, `job_id`, `archive_sha256`,
`started_at_utc`, `finished_at_utc`, and nonempty `evidence`. Status must be
`PASS`; `FAIL`, `BLOCKED`, `NOT_RUN`, `SKIPPED`, omission and scope-exclusion
are not accepted. The result's archive SHA must equal the manifest's original
archive SHA. `job_id` must identify the successful `accept-<test_id>` job in
the exact acceptance run/attempt; result timestamps must fall within that
job's execution. Every evidence entry has exactly `path` and `sha256`; the
file must be present and hash-match, with no path traversal, symlink or
unlisted file. Evidence should be redacted; never upload credentials, private
keys, PINs, biometric records, raw authorization QR codes, or node secrets.

The fixed required deployment and upgrade set is **D01-D18, H01-H10,
R01-R12 and U01-U17** from the 2026-09-27 deployment acceptance plan. This
includes clean install, ordinary-node join, synchronization, restart and
recovery, real TLS issuance/reporting, SSH hardening and public lockdown,
re-genesis isolation, and authorized upgrade/rollback. A conditional branch
such as TPM/no-TPM must be truthfully covered by its job or remain blocked;
this contract has no `SKIP` escape. Cross-client C01-C10 and broader L2/L3
acceptance remain separate work and are not claimed by this node stable gate.

## Before enabling stable

1. Implement and review a real acceptance workflow and collectors. Each
   `accept-ID` job must validate the same downloaded original archive SHA,
   run the specified system-level scenario on isolated real Linux/systemd
   nodes where applicable, and save independently obtained evidence. Build,
   unit tests, source-string checks, success toasts and operator-edited PASS
   JSON are not sufficient. Do not publish that workflow as existing until it
   has been implemented and reviewed.
2. Have an aggregation job reject missing/failed/skipped jobs, bind the exact
   candidate metadata and evidence hashes, emit the manifest, and attest
   **that manifest** from the same run/attempt. Publish one immutable artifact
   named `node-deployment-acceptance`. Preserve the original failure records
   outside the promotable artifact for audit; never rewrite them into PASS.
3. After review, pin that workflow path and exact commit in
   `acceptance-policy.json`, and verify token access to the workflow run,
   artifact, jobs and attestation. Protect changes to the policy, workflow and
   producer code with repository review controls. Exercise an actual GitHub
   acceptance run and a stable dry run before any publication. Keep
   `trusted_source: null` until those facts exist.

Local unit tests validate parsing and rejection behavior only. Synthetic
receipt fixtures do not cryptographically verify a GitHub attestation, prove
system tests ran, or authorize a stable release.
