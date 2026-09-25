# tden-node-releases

Immutable, digest-verified TDEN node release artifacts.

Official candidates are built by GitHub Actions from exact `tden-chain`,
`tden-gateway`, and `tden-deploy` revisions. A candidate can be published as an
explicit preview for controlled installation tests; it cannot become stable
until the multi-node acceptance suite passes. Publication preserves the
same archive digest; it never rebuilds the package on an operator workstation
or node.

## Release flow

1. Run `Build TDEN node candidate` with exact Chain, Gateway, and Deploy commits.
2. Download that workflow artifact directly on the validation nodes.
3. Complete clean install, join, synchronization, restart, interruption, TLS,
   SSH-hardening, and public-lockdown acceptance.
4. Run `Publish TDEN node candidate` with the candidate run ID, archive SHA-256
   and release channel. The default `preview` channel is not a stable promotion.
   Select `stable` only after all required deployment acceptance is complete.

The promotion workflow verifies the successful build workflow, artifact file
set, archive digest, size, source revisions, and candidate description before
publishing the unchanged archive. Both channels verify GitHub-hosted build
attestations and the uploaded asset digests. An interrupted preview draft with
the same digest tag can be resumed; published releases are never overwritten.
Stable publication still uses the `stable-node-release` GitHub environment.
Configure required reviewers there to retain a separate human approval boundary.

A published preview can be promoted to stable through this same workflow. It
rechecks provenance and all three existing asset digests against the original
candidate, skips asset upload, and changes only release metadata. Existing stable
releases cannot be replaced or downgraded. 已发布的预览版可在原附件逐项复核后晋升为
稳定版，只修改发布元数据，不覆盖附件；已有稳定版不能替换或降级。

预览版仅用于受控安装测试，不能代替稳定版验收，也不会更新 TUF 授权或链上 DAO 策略。
工作流直接在 GitHub 内下载候选包并发布原包，不经过运营者电脑或节点中转。

`release-policy.json` pins the bootstrap trust-template and TUF-root digests
accepted by both candidate construction and promotion. Rotating either root is
a separate reviewed policy and client/Console release, not an ordinary node
package update.

## Runtime Bundle Provenance

New builds require `tden-node-runtime-upgrade` as a manifested, mode-0755 Linux amd64 ELF with clean Gateway Go/VCS metadata. The package metadata must bind `configuration_profile_sha256` to `configuration-profile.json`, copied byte-for-byte from `deploy/node-installer/configuration-profile.json`. It accepts exactly four fields: `protocol=tden:node-runtime-configuration-profile:v1`, `profile_id=public-node-runtime-rebase-v1`, `migration=preserve-state-and-rebase-runtime-v1`, and `role_artifacts`, a string-to-string object containing the exact nine role-to-binary mappings enforced by Gateway's `internal/nodecontrol/node_runtime_package.go`. Missing, extra or duplicate fields/roles and changed mappings are rejected. Final source commits remain pending; do not dispatch until approved. The deployment repository owns the helper build, archive executable allow-list, fixed profile and its semantic tests. The profile remains inside the original flat tar.gz, not a separate TUF target; the offline v2 manifest must also bind its digest.

`candidate-build.json` keeps its v1 protocol and existing fields, adding `runtime_bundle`, the workflow commit/attempt and exact repository-to-commit mappings. `runtime_bundle` binds the original archive's `package.sha256`, `package-metadata.json`, configuration profile and helper. CI checks every archive member against the complete manifest without extracting or executing it.

All nine profile-mapped binaries must exist in the archive and be covered by `package.sha256`. Runtime bundles also require the fixed regular member `node-runtime-files.py`, covered by the same manifest and thus the original archive/manifest digest bindings. Packaging tests check presence, uniqueness and checksums only; they do not execute this script or establish file-transaction, rollback or systemd acceptance. No profile or candidate-description schema field is added for this member.

The existing single-subject archive attestation is unchanged. A **separate GitHub attestation** now covers `candidate-build.json`, cryptographically binding its archive digest and all Chain/Gateway/Deploy/release-workflow revisions. The default GitHub SLSA `resolvedDependencies` still describes the workflow repository, not all checked-out repositories; the separately attested description supplies those additional bindings. Promotion requires both verified subjects from the exact build run, attempt and workflow commit, and retains the verifier JSON as an Actions artifact. The three public release assets are unchanged.

Legacy candidates without the new attestation step remain on the v1 component path. A new runtime build cannot omit its description or fall back to legacy provenance. These checks do not create SPDX, offline release/DAO signatures, TUF targets or deployment acceptance, and do not authorize stable promotion.

Local regression checks: `python3 -B -m unittest discover -s scripts -p 'test_*.py' -v`. Receipt fixtures test binding rules only, not cryptographic verification. Actual GitHub verification requires the completed build and publish workflows.

新包须包含可执行 helper、固定 profile 及完整清单绑定；原归档验签和旧 v1 组件通路保留。候选描述单独由 GitHub 验签，不代表离线 DAO 签名或整节点验收。最终接口和提交确认前不发起构建，不晋升 stable 或 TUF。
