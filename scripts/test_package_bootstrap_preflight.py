from contextlib import redirect_stderr
import io
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

    def assert_rejected(self, error, phase, kind, effect, code="unavailable"):
        output = io.StringIO()
        with effect, redirect_stderr(output), self.assertRaises(type(error)) as caught:
            self.run_preflight()
        self.assertIs(caught.exception, error)
        self.assertEqual(output.getvalue(),
                         f"bootstrap-preflight-rejected last_phase={phase} kind={kind} returncode={code}\n")

    def test_policy_failure_label_and_original_exception(self):
        error = ValueError("SENSITIVE_POLICY_SENTINEL")
        self.assert_rejected(error, "read-policy", "invalid-value",
                             patch.object(preflight.candidate, "read_json", side_effect=error))

    def test_archive_failure_label_prevents_execution(self):
        error = ValueError("SENSITIVE_ARCHIVE_SENTINEL")
        with patch.object(preflight.subprocess, "run") as run:
            self.assert_rejected(error, "inspect-archive", "invalid-value",
                                 patch.object(preflight.candidate, "inspect_archive", side_effect=error))
        run.assert_not_called()

    def test_missing_public_field_is_redacted(self):
        error = KeyError("SENSITIVE_FIELD_SENTINEL")
        self.assert_rejected(error, "read-public-trust", "missing-field",
                             patch.object(preflight.candidate, "read_json",
                                          side_effect=[self.package.policy, error]))

    def test_resolve_failure_label(self):
        error = OSError("SENSITIVE_PATH_SENTINEL")
        self.assert_rejected(error, "resolve-paths", "os-error",
                             patch.object(preflight.Path, "resolve", side_effect=error))

    def test_temporary_creation_failure_label(self):
        error = OSError("SENSITIVE_TEMP_SENTINEL")
        self.assert_rejected(error, "create-temporary", "os-error",
                             patch.object(preflight.tempfile, "TemporaryDirectory", side_effect=error))

    def test_extraction_failure_label(self):
        error = preflight.tarfile.ExtractError("SENSITIVE_TAR_SENTINEL")
        self.assert_rejected(error, "extract-archive", "archive-error",
                             patch.object(preflight.tarfile.TarFile, "extractall", side_effect=error))

    def test_invocation_preparation_failure_does_not_claim_execution(self):
        error = OSError("SENSITIVE_TRUST_PATH_SENTINEL")
        with patch.object(preflight.subprocess, "run") as run:
            self.assert_rejected(error, "prepare-invocation", "os-error",
                                 patch.object(preflight.candidate, "file_sha", side_effect=error))
        run.assert_not_called()

    def test_child_exit_redacts_command_stdout_and_stderr_and_cleans(self):
        error = subprocess.CalledProcessError(
            7, ["SENSITIVE_COMMAND_SENTINEL"], output="SENSITIVE_STDOUT_SENTINEL",
            stderr="SENSITIVE_STDERR_SENTINEL")
        package_paths = []

        def execute(argv, **options):
            package_paths.append(Path(argv[0]).parent)
            self.assertTrue(options["capture_output"])
            self.assertTrue(options["check"])
            self.assertEqual(options["timeout"], 60)
            raise error

        self.assert_rejected(error, "execute-bootstrap", "subprocess-exit",
                             patch.object(preflight.subprocess, "run", side_effect=execute), "7")
        self.assertEqual(len(package_paths), 1)
        self.assertFalse(package_paths[0].exists())

    def test_timeout_redacts_output_and_preserves_rejection(self):
        error = subprocess.TimeoutExpired("SENSITIVE_COMMAND", 60, output="SENSITIVE_OUTPUT",
                                          stderr="SENSITIVE_STDERR")
        self.assert_rejected(error, "execute-bootstrap", "subprocess-timeout",
                             patch.object(preflight.subprocess, "run", side_effect=error))

    def test_os_spawn_error_does_not_become_success(self):
        error = PermissionError("SENSITIVE_BINARY_PATH")
        self.assert_rejected(error, "execute-bootstrap", "os-error",
                             patch.object(preflight.subprocess, "run", side_effect=error))

    def test_other_subprocess_error_is_fixed_label(self):
        error = subprocess.SubprocessError("SENSITIVE_SUBPROCESS")
        self.assert_rejected(error, "execute-bootstrap", "subprocess-error",
                             patch.object(preflight.subprocess, "run", side_effect=error))

    def test_wrong_network_id_is_labeled_without_output(self):
        output = io.StringIO()
        with patch.object(preflight.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, "SENSITIVE_DIFFERENT_NETWORK", "")), redirect_stderr(output):
            with self.assertRaisesRegex(ValueError, "different network ID"):
                self.run_preflight()
        self.assertEqual(output.getvalue(),
                         "bootstrap-preflight-rejected last_phase=compare-network-id kind=invalid-value returncode=unavailable\n")

    def test_cleanup_error_reports_last_entered_phase(self):
        error = OSError("SENSITIVE_CLEANUP_PATH")
        root = self.root / "cleanup-fixture"
        root.mkdir()
        with patch.object(preflight.tempfile, "TemporaryDirectory") as temporary:
            temporary.return_value.__enter__.return_value = str(root)
            temporary.return_value.__exit__.side_effect = error
            self.assert_rejected(error, "cleanup-temporary", "os-error",
                                 patch.object(preflight.subprocess, "run",
                                              return_value=subprocess.CompletedProcess([], 0, "tden-ci-preflight", "")))

    def test_returncode_and_phase_allowlist(self):
        for code, expected in ((-9, "-9"), (255, "255"), (256, "unavailable"),
                               (True, "unavailable"), ("SENSITIVE_CODE", "unavailable")):
            with self.subTest(code_type=type(code).__name__):
                output = io.StringIO()
                with redirect_stderr(output):
                    preflight.report_rejection("SENSITIVE_PHASE",
                                               subprocess.CalledProcessError(code, "SENSITIVE_COMMAND"))
                self.assertEqual(output.getvalue(),
                                 f"bootstrap-preflight-rejected last_phase=unknown kind=subprocess-exit returncode={expected}\n")

    def test_diagnostic_write_failure_preserves_original_rejection(self):
        error = subprocess.CalledProcessError(3, "SENSITIVE_COMMAND")
        with patch.object(preflight.subprocess, "run", side_effect=error), \
                patch("builtins.print", side_effect=OSError("SENSITIVE_LOG_PATH")):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                self.run_preflight()
        self.assertIs(caught.exception, error)

    def test_success_does_not_emit_rejection(self):
        output = io.StringIO()
        with patch.object(preflight.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "tden-ci-preflight\n", "")), \
                redirect_stderr(output), patch("builtins.print") as printer:
            self.run_preflight()
        self.assertEqual(output.getvalue(), "")
        printer.assert_called_once_with(
            "PASS: archived bootstrap accepted original package metadata/profile and signed public bootstrap material")

    def test_closed_stderr_preserves_original_rejection(self):
        output = io.StringIO()
        output.close()
        error = subprocess.CalledProcessError(5, "SENSITIVE_COMMAND")
        with patch.object(preflight.subprocess, "run", side_effect=error), redirect_stderr(output):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                self.run_preflight()
        self.assertIs(caught.exception, error)

    def test_cleanup_can_override_body_failure_without_claiming_root_cause(self):
        body_error = subprocess.CalledProcessError(5, "SENSITIVE_COMMAND")
        cleanup_error = OSError("SENSITIVE_CLEANUP_PATH")
        root = self.root / "paired-cleanup-fixture"
        root.mkdir()
        with patch.object(preflight.tempfile, "TemporaryDirectory") as temporary:
            temporary.return_value.__enter__.return_value = str(root)
            temporary.return_value.__exit__.side_effect = cleanup_error
            self.assert_rejected(cleanup_error, "execute-bootstrap", "os-error",
                                 patch.object(preflight.subprocess, "run", side_effect=body_error))
        self.assertIs(cleanup_error.__context__, body_error)

    def test_cli_preserves_exit_one_and_generic_message(self):
        output = io.StringIO()
        with patch.object(preflight.candidate, "inspect_archive", side_effect=ValueError("SENSITIVE_REASON")), \
                redirect_stderr(output), self.assertRaises(SystemExit) as caught:
            preflight.main(["--archive", str(self.root / preflight.candidate.ARCHIVE),
                            "--policy", str(self.policy), "--version", self.package.version,
                            "--materials", str(self.materials)])
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(output.getvalue(),
                         "bootstrap-preflight-rejected last_phase=inspect-archive kind=invalid-value returncode=unavailable\n"
                         "packaged bootstrap preflight failed; package or signed public materials were rejected\n")


if __name__ == "__main__":
    unittest.main()
