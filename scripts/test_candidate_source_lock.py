import copy
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import candidate_metadata as candidate
import check_candidate_source_lock as lock
import test_candidate_metadata as fixtures


class CandidateSourceLockTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CandidateMetadataTests(methodName="test_runtime_binds_original_manifest_metadata_profile_and_helper")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.data = self.fixture.description()
        # CI checks out dependencies inside source; local repositories are siblings.
        # CI 的依赖位于 source 下；本地依赖仓库与发布仓库并列。
        repository = Path(__file__).resolve().parents[1]
        deploy_sources = (repository / "source/deploy", repository.parent / "deploy")
        deploy_source = next((source for source in deploy_sources
                              if (source / "node-installer/assert-release-isolation.ps1").is_file()),
                             deploy_sources[0])
        self.args = SimpleNamespace(
            **{key: self.data[key] for key in (*candidate.REPOSITORIES, "workflow_commit", "version", "archive_sha256")},
            run_id=self.fixture.run["id"], run_attempt=self.fixture.run["run_attempt"],
            directory=self.fixture.root, repository=self.fixture.repo,
            deploy_source=deploy_source,
        )
        for field, filename, data in (
            ("run", "run.json", self.fixture.run),
            ("policy", "policy.json", self.fixture.policy),
            ("jobs", "jobs.json", [{"jobs": [{"steps": [{"name": candidate.DESCRIPTION_STEP, "conclusion": "success"}]}]}]),
            ("archive_receipt", "archive-receipt.json", self.fixture.receipt(candidate.ARCHIVE, self.data["archive_sha256"])),
            ("description_receipt", "description-receipt.json", self.fixture.receipt("candidate-build.json", "0" * 64)),
        ):
            setattr(self.args, field, self.fixture.root / filename)
            self.fixture.write_json(filename, data)
        self.save_description()

    def save_description(self):
        self.fixture.write_json("candidate-build.json", self.data)
        self.fixture.write_json("description-receipt.json", self.fixture.receipt(
            "candidate-build.json", candidate.file_sha(self.fixture.root / "candidate-build.json")))

    def test_exact_source_lock_and_existing_verifier_compose(self):
        with patch.object(lock, "scan_isolation") as scan, patch("builtins.print"):
            lock.check(self.args)
        scan.assert_called_once_with(self.fixture.root / candidate.ARCHIVE, self.args.deploy_source, self.args.deploy_commit)

    def test_consistent_attested_old_source_is_not_final_source(self):
        for key in (*candidate.REPOSITORIES, "workflow_commit"):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data[key] = "9" * 40
                data["source_repositories"] = candidate.source_repositories(data)
                with self.assertRaisesRegex(ValueError, f"final source lock mismatch: {key}"):
                    lock.check_lock(data, self.fixture.run, self.args)

    def test_old_59_version_cannot_be_relabelled_60(self):
        self.args.version = "0.12.60"
        self.data["version"] = "0.12.59"
        with self.assertRaisesRegex(ValueError, "version lock mismatch"):
            lock.check_lock(self.data, self.fixture.run, self.args)

    def test_publisher_accepts_consistent_old_ref_but_final_lock_rejects_it(self):
        self.data["gateway_commit"] = "9" * 40
        self.data["source_repositories"] = candidate.source_repositories(self.data)
        self.save_description()
        with patch("builtins.print"):
            candidate.verify(self.args, repository=self.args.repository, expected_sha256=self.args.archive_sha256)
        with patch.object(lock, "scan_isolation") as scan:
            with self.assertRaisesRegex(ValueError, "final source lock mismatch: gateway_commit"):
                lock.check(self.args)
        scan.assert_not_called()

    def test_missing_description_receipt_fails_before_scan(self):
        self.fixture.write_json("description-receipt.json", [])
        with patch.object(lock, "scan_isolation") as scan, patch("builtins.print"):
            with self.assertRaisesRegex(ValueError, "no verified attestation"):
                lock.check(self.args)
        scan.assert_not_called()

    def test_archive_run_attempt_and_runtime_are_locked(self):
        for field, value in (("archive_sha256", "0" * 64), ("run_id", 1), ("run_attempt", 1)):
            with self.subTest(field=field):
                args = copy.copy(self.args)
                setattr(args, field, value)
                with self.assertRaisesRegex(ValueError, "lock mismatch"):
                    lock.check_lock(self.data, self.fixture.run, args)
        del self.data["runtime_bundle"]
        with self.assertRaisesRegex(ValueError, "requires runtime provenance"):
            lock.check_lock(self.data, self.fixture.run, self.args)

    def test_final_refs_must_be_full_lowercase_commit_hashes(self):
        for key in (*candidate.REPOSITORIES, "workflow_commit"):
            for bad in ("main", "abcdef", "A" * 40, ""):
                with self.subTest(key=key, bad=bad):
                    args = copy.copy(self.args)
                    setattr(args, key, bad)
                    with self.assertRaisesRegex(ValueError, "invalid expected source"):
                        lock.check_lock(self.data, self.fixture.run, args)

    def test_reissued_description_receipt_cannot_change_pinned_root(self):
        for key in candidate.ROOT_FILES:
            with self.subTest(key=key):
                saved = self.data[key]
                self.data[key] = "0" * 64
                self.save_description()
                with self.assertRaisesRegex(ValueError, "candidate trust mismatch"), patch("builtins.print"):
                    lock.check(self.args)
                self.data[key] = saved

    def test_archive_mutation_prevents_isolation_and_success(self):
        with (self.fixture.root / candidate.ARCHIVE).open("ab") as stream:
            stream.write(b"changed")
        with patch.object(lock, "scan_isolation") as scan, patch("builtins.print"):
            with self.assertRaisesRegex(ValueError, "approved digest"):
                lock.check(self.args)
        scan.assert_not_called()

    def test_scanner_requires_same_clean_deploy_source(self):
        for outputs, error in ((["9" * 40], "commit mismatch"), ([self.args.deploy_commit, " M scanner"], "clean Deploy")):
            with patch.object(lock.subprocess, "check_output", side_effect=outputs), patch.object(lock.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, error):
                    lock.scan_isolation(self.fixture.root / candidate.ARCHIVE, self.args.deploy_source, self.args.deploy_commit)
                run.assert_not_called()

    def test_manifested_synthetic_identity_and_runtime_hooks_fail_existing_scanner(self):
        # Real existing scanner, synthetic archive fixtures, no archived program execution.
        for marker in (b"tden.local.e2e.synthetic", b"TDEN_ENABLE_TEST_TOKEN_ISSUANCE", "TDEN_TEST_HARNESS".encode("utf-16-le")):
            with self.subTest(marker=marker):
                self.fixture.files["tden-gateway"] = marker
                self.fixture.write_archive()
                self.fixture.inspect()
                with patch.object(lock.subprocess, "check_output", side_effect=[self.args.deploy_commit, ""]):
                    with self.assertRaises(subprocess.CalledProcessError):
                        lock.scan_isolation(self.fixture.root / candidate.ARCHIVE, self.args.deploy_source, self.args.deploy_commit)

    def test_clean_archive_passes_existing_scanner(self):
        with patch.object(lock.subprocess, "check_output", side_effect=[self.args.deploy_commit, ""]):
            lock.scan_isolation(self.fixture.root / candidate.ARCHIVE, self.args.deploy_source, self.args.deploy_commit)


if __name__ == "__main__":
    unittest.main()
