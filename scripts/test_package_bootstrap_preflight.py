import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import package_bootstrap_preflight as preflight
import test_candidate_metadata as fixtures


class PackageBootstrapPreflightTests(unittest.TestCase):
    def setUp(self):
        self.package = fixtures.CandidateMetadataTests()
        self.package.setUp()
        self.addCleanup(self.package.doCleanups)
        self.package.files["tden-node-bootstrap"] = b"fixture only; never execute"
        self.package.write_archive()
        self.root = self.package.root
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps(self.package.policy))
        self.materials = self.root / "public-materials"
        self.materials.mkdir()
        (self.materials / "bootstrap-trust.json").write_text(json.dumps({"network_id": "tden-ci-preflight"}))
        for name in ("bootstrap-manifest.json", "genesis.json"):
            (self.materials / name).write_text("{}")

    def run_preflight(self):
        preflight.preflight(self.root / preflight.candidate.ARCHIVE, self.policy, self.package.version, self.materials)

    def test_executes_original_archived_binary_and_metadata(self):
        def execute(argv, **options):
            package = Path(argv[0]).parent
            for name in ("tden-node-bootstrap", "package-metadata.json", "configuration-profile.json", "bootstrap-trust-template.json"):
                self.assertEqual((package / name).read_bytes(), self.package.files[name])
            self.assertEqual(argv[argv.index("--package-metadata") + 1], str(package / "package-metadata.json"))
            self.assertEqual(argv[argv.index("--manifest") + 1], str(self.materials / "bootstrap-manifest.json"))
            self.assertEqual(argv[argv.index("--trust-sha256") + 1], preflight.candidate.file_sha(self.materials / "bootstrap-trust.json"))
            self.assertTrue(options["check"])
            self.assertEqual(options["timeout"], 60)
            return subprocess.CompletedProcess(argv, 0, "tden-ci-preflight\n", "")

        with patch.object(preflight.subprocess, "run", side_effect=execute) as run, patch("builtins.print"):
            self.run_preflight()
        run.assert_called_once()

    def test_packaged_parser_failure_is_not_accepted(self):
        failure = subprocess.CalledProcessError(1, "packaged-bootstrap", stderr="node package metadata is invalid")
        with patch.object(preflight.subprocess, "run", side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError):
                self.run_preflight()

    def test_success_with_wrong_output_is_not_accepted(self):
        with patch.object(preflight.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "help text", "")):
            with self.assertRaisesRegex(ValueError, "different network ID"):
                self.run_preflight()

    def test_bad_archive_is_rejected_before_execution(self):
        self.package.metadata["configuration_profile_sha256"] = "0" * 64
        self.package.write_archive()
        with patch.object(preflight.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                self.run_preflight()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
