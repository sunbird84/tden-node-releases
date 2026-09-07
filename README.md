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

预览版仅用于受控安装测试，不能代替稳定版验收，也不会更新 TUF 授权或链上 DAO 策略。
工作流直接在 GitHub 内下载候选包并发布原包，不经过运营者电脑或节点中转。

`release-policy.json` pins the bootstrap trust-template and TUF-root digests
accepted by both candidate construction and promotion. Rotating either root is
a separate reviewed policy and client/Console release, not an ordinary node
package update.
