# Local TEST recovery previews

The local path publishes an existing, locally built TEST node archive without
running GitHub Actions. It records the actual build interval, source commits,
package digests and local verification. It does not claim a hosted attestation
or grant permission to upgrade a node.

Use a clean Linux control checkout and clean source checkouts matching the build
receipt. The private request file follows `tden:node-local-preview-request:v1`
in `scripts/local_candidate_metadata.py`; it contains local paths and must stay
local. The public descriptor contains hashes and public source references only.

1. Create `candidate-build.json` with the local Python creator:

   ```text
   python3 -I -B scripts/local_candidate_metadata.py create --request REQUEST.json --output ASSETS/candidate-build.json
   ```

2. Keep exactly three files in the release asset directory:
   `tden-node-linux-amd64.tar.gz`, its `.sha256` file, and `candidate-build.json`.
   The checksum line uses two spaces before the archive filename and ends in LF.

3. On Windows, verify the actual release inputs without contacting GitHub:

   ```text
   node scripts/publish_local_preview.mjs --request E:/path/REQUEST.json --asset-dir E:/path/ASSETS
   ```

4. Add `--publish` to publish the verified preview using the existing GitHub CLI
   login. The publisher uses Ubuntu under WSL for verification, creates a draft,
   uploads the exact files, and checks GitHub asset digests before publishing.
   It never promotes to stable or latest. A failed operation leaves its state
   available for inspection; published assets cannot be replaced. Reinvocation
   revalidates everything and can fill missing assets in a matching draft.

The tag binds the archive digest and resolves to the control commit. Existing
hosted creation, attestation and promotion workflows remain independent.
Normal updates still use Core Team organization authority. An initial-sync
recovery additionally needs the original node's owner, signed history, current
eligibility, exact phase approval and the existing stop/hold checks.

Local checks:

```text
python3 -I -B scripts/test_local_candidate_metadata.py
node --test scripts/test_publish_local_preview.mjs
```

The Node transport tests simulate GitHub. Actual publication and node recovery
must be recorded separately from these tests and from local compilation.
