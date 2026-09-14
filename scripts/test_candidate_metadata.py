import copy
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import candidate_metadata as candidate


class CandidateMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.version = "0.12.27"
        self.repo = "sunbird84/tden-node-releases"
        self.run = {"id": 12345, "run_attempt": 2, "head_sha": "4" * 40}
        self.files = {
            "bootstrap-trust-template.json": b'{"bootstrap":true}\n',
            "tuf-root.json": b'{"root":true}\n',
            "package-version.txt": (self.version + "\n").encode(),
            "configuration-profile.json": json.dumps({
                "protocol": "tden:node-runtime-configuration-profile:v1",
                "profile_id": "public-node-runtime-rebase-v1",
                "migration": "preserve-state-and-rebase-runtime-v1",
                "role_artifacts": {
                    "chain": "tdend", "gateway": "tden-gateway", "identity": "tden-identity-node",
                    "map": "tden-map-tile-service", "node_relay": "tden-node-coordinator",
                    "public_supervisor": "tden-public-supervisor", "service_approver": "tden-service-approverd",
                    "service_repair": "tden-service-repaird", "service_worker": "tden-service-workerd",
                },
            }).encode(),
            candidate.HELPER: b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00fixture",
            candidate.FILE_TRANSACTION_SCRIPT: b'raise RuntimeError("packaging fixture only; never execute")\n',
        }
        for name in ("tdend", "tden-gateway", "tden-identity-node", "tden-map-tile-service",
                     "tden-node-coordinator", "tden-public-supervisor", "tden-service-approverd",
                     "tden-service-repaird", "tden-service-workerd"):
            self.files[name] = ("packaging-only fixture: " + name).encode()
        self.policy = {key: candidate.sha(self.files[name]) for key, name in candidate.ROOT_FILES.items()}
        self.metadata = {
            "protocol": "tden:node-runtime-package:v2", "version": self.version,
            "platform": "linux-amd64", **self.policy,
            "configuration_profile_sha256": candidate.sha(self.files["configuration-profile.json"]),
        }
        self.write_archive()

    def write_archive(self, extra=None, mode=0o755, bad_manifest=None):
        self.files["package-metadata.json"] = json.dumps(self.metadata).encode()
        self.files["package.sha256"] = "".join(
            f"{candidate.sha(body)}  {name}\n" for name, body in sorted(self.files.items()) if name != "package.sha256"
        ).encode()
        if bad_manifest is not None:
            self.files["package.sha256"] = bad_manifest
        with tarfile.open(self.root / candidate.ARCHIVE, "w:gz") as archive:
            for name, body in self.files.items():
                member = tarfile.TarInfo("./" + name)
                member.size = len(body)
                member.mode = mode if name == candidate.HELPER else 0o644
                archive.addfile(member, io.BytesIO(body))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b""))

    def inspect(self, runtime=True):
        return candidate.inspect_archive(self.root / candidate.ARCHIVE, self.policy, self.version, runtime)

    def description(self):
        data = {
            "protocol": "tden:node-candidate-build:v1", "workflow_repository": self.repo,
            "workflow_run_id": str(self.run["id"]), "workflow_run_attempt": str(self.run["run_attempt"]),
            "workflow_commit": self.run["head_sha"], "version": self.version,
            "archive_sha256": candidate.file_sha(self.root / candidate.ARCHIVE),
            "archive_bytes": (self.root / candidate.ARCHIVE).stat().st_size,
            "chain_commit": "1" * 40, "gateway_commit": "2" * 40, "deploy_commit": "3" * 40,
            "runtime_bundle": self.inspect(), **self.policy,
        }
        data["source_repositories"] = candidate.source_repositories(data)
        return data

    def check_description(self, data, runtime=True):
        candidate.validate_description(data, self.run, self.repo, candidate.file_sha(self.root / candidate.ARCHIVE), (self.root / candidate.ARCHIVE).stat().st_size, runtime)

    def receipt(self, name, digest):
        invocation = f"https://github.com/{self.repo}/actions/runs/{self.run['id']}/attempts/{self.run['run_attempt']}"
        return [{"verificationResult": {
            "signature": {"certificate": {
                "issuer": "https://token.actions.githubusercontent.com", "runInvocationURI": invocation,
                "buildSignerURI": f"https://github.com/{self.repo}/{candidate.WORKFLOW}@refs/heads/main",
                "sourceRepositoryDigest": self.run["head_sha"], "buildSignerDigest": self.run["head_sha"],
                "runnerEnvironment": "github-hosted",
            }},
            "verifiedTimestamps": [{"type": "fixture-not-cryptographic-proof"}],
            "statement": {
                "_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": name, "digest": {"sha256": digest}}],
                "predicate": {"runDetails": {"metadata": {"invocationId": invocation}}},
            },
        }}]

    def test_runtime_binds_original_manifest_metadata_profile_and_helper(self):
        runtime = self.inspect()
        self.assertEqual(runtime["package_manifest_sha256"], candidate.sha(self.files["package.sha256"]))
        self.assertEqual(runtime["package_metadata_sha256"], candidate.sha(self.files["package-metadata.json"]))
        self.assertEqual(runtime["configuration_profile_sha256"], candidate.sha(self.files["configuration-profile.json"]))
        self.assertEqual(runtime["helper"]["sha256"], candidate.sha(self.files[candidate.HELPER]))
        self.check_description(self.description())

    def test_legacy_component_description_remains_valid(self):
        del self.files[candidate.HELPER]
        del self.files[candidate.FILE_TRANSACTION_SCRIPT]
        del self.files["configuration-profile.json"]
        del self.metadata["configuration_profile_sha256"]
        self.write_archive()
        self.assertIsNone(self.inspect(False))
        data = self.description_legacy()
        self.check_description(data, False)

    def description_legacy(self):
        return {
            "protocol": "tden:node-candidate-build:v1", "workflow_repository": self.repo,
            "workflow_run_id": str(self.run["id"]), "version": self.version,
            "archive_sha256": candidate.file_sha(self.root / candidate.ARCHIVE),
            "archive_bytes": (self.root / candidate.ARCHIVE).stat().st_size,
            "chain_commit": "1" * 40, "gateway_commit": "2" * 40, "deploy_commit": "3" * 40, **self.policy,
        }

    def test_missing_helper_rejected(self):
        del self.files[candidate.HELPER]
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "helper missing"):
            self.inspect()

    def test_file_transaction_script_required_under_fixed_name(self):
        body = self.files.pop(candidate.FILE_TRANSACTION_SCRIPT)
        for replacement in (None, "other-runtime-files.py"):
            with self.subTest(replacement=replacement):
                if replacement:
                    self.files[replacement] = body
                self.write_archive()
                with self.assertRaisesRegex(ValueError, "node-runtime-files.py missing"):
                    self.inspect()

    def test_file_transaction_script_must_be_listed_in_manifest(self):
        manifest = b"".join(line for line in self.files["package.sha256"].splitlines(keepends=True)
                            if not line.endswith(b"  node-runtime-files.py\n"))
        self.assertNotEqual(manifest, self.files["package.sha256"])
        self.write_archive(bad_manifest=manifest)
        with self.assertRaisesRegex(ValueError, "member set mismatch"):
            self.inspect()

    def test_file_transaction_script_digest_mismatch_rejected(self):
        manifest = self.files["package.sha256"]
        self.files[candidate.FILE_TRANSACTION_SCRIPT] += b"# changed\n"
        self.write_archive(bad_manifest=manifest)
        with self.assertRaisesRegex(ValueError, "member digest mismatch: node-runtime-files.py"):
            self.inspect()

    def test_file_transaction_script_manifest_entry_needs_actual_member(self):
        manifest = self.files["package.sha256"]
        del self.files[candidate.FILE_TRANSACTION_SCRIPT]
        self.write_archive(bad_manifest=manifest)
        with self.assertRaisesRegex(ValueError, "member set mismatch"):
            self.inspect()

    def test_file_transaction_script_must_be_unique_regular_member(self):
        body = self.files[candidate.FILE_TRANSACTION_SCRIPT]
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.REGTYPE):
            with self.subTest(kind=kind):
                if kind == tarfile.REGTYPE:
                    self.files[candidate.FILE_TRANSACTION_SCRIPT] = body
                else:
                    self.files.pop(candidate.FILE_TRANSACTION_SCRIPT, None)
                member = tarfile.TarInfo(candidate.FILE_TRANSACTION_SCRIPT)
                member.type = kind
                if kind != tarfile.REGTYPE:
                    member.linkname = candidate.HELPER
                self.write_archive(extra=member)
                with self.assertRaisesRegex(ValueError, "duplicate or non-regular member: node-runtime-files.py"):
                    self.inspect()

    def test_file_transaction_script_bytes_bound_without_execution(self):
        with patch.object(candidate.subprocess, "check_output") as execute:
            before = self.inspect()
            self.files[candidate.FILE_TRANSACTION_SCRIPT] += b"# changed\n"
            self.write_archive()
            after = self.inspect()
        execute.assert_not_called()
        self.assertNotEqual(before["package_manifest_sha256"], after["package_manifest_sha256"])
        self.assertEqual(after["package_manifest_sha256"], candidate.sha(self.files["package.sha256"]))

    def test_non_executable_helper_rejected(self):
        self.write_archive(mode=0o644)
        with self.assertRaisesRegex(ValueError, "0755"):
            self.inspect()

    def test_non_elf_helper_rejected(self):
        self.files[candidate.HELPER] = b"not an executable"
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "ELF64"):
            self.inspect()

    def test_missing_profile_binding_rejected(self):
        del self.metadata["configuration_profile_sha256"]
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "must bind"):
            self.inspect()

    def test_profile_digest_mismatch_rejected(self):
        self.metadata["configuration_profile_sha256"] = "0" * 64
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "one manifested JSON"):
            self.inspect()

    def test_duplicate_profile_digest_rejected(self):
        self.files["duplicate.json"] = self.files["configuration-profile.json"]
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "one manifested JSON"):
            self.inspect()

    def test_profile_must_be_object(self):
        self.files["configuration-profile.json"] = b"[]"
        self.metadata["configuration_profile_sha256"] = candidate.sha(b"[]")
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "must be an object"):
            self.inspect()

    def test_profile_json_duplicate_keys_rejected(self):
        self.files["configuration-profile.json"] = b'{"a":1,"a":2}'
        self.metadata["configuration_profile_sha256"] = candidate.sha(self.files["configuration-profile.json"])
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.inspect()

    def test_profile_member_name_is_fixed(self):
        self.files["another-profile.json"] = self.files.pop("configuration-profile.json")
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "must use fixed member"):
            self.inspect()

    def test_frozen_profile_fields_must_match(self):
        original = json.loads(self.files["configuration-profile.json"])
        for key in ("protocol", "profile_id", "migration"):
            with self.subTest(key=key):
                profile = {**original, key: "wrong"}
                self.files["configuration-profile.json"] = json.dumps(profile).encode()
                self.metadata["configuration_profile_sha256"] = candidate.sha(self.files["configuration-profile.json"])
                self.write_archive()
                with self.assertRaisesRegex(ValueError, f"profile {key} mismatch"):
                    self.inspect()

    def write_profile(self, profile):
        self.files[candidate.PROFILE_NAME] = json.dumps(profile).encode()
        self.metadata["configuration_profile_sha256"] = candidate.sha(self.files[candidate.PROFILE_NAME])
        self.write_archive()

    def test_profile_unknown_fields_rejected(self):
        profile = json.loads(self.files[candidate.PROFILE_NAME])
        profile["extra"] = "unsupported"
        self.write_profile(profile)
        with self.assertRaisesRegex(ValueError, "exactly four fixed fields"):
            self.inspect()

    def test_profile_missing_fields_rejected(self):
        original = json.loads(self.files[candidate.PROFILE_NAME])
        for key in original:
            with self.subTest(key=key):
                profile = copy.deepcopy(original)
                del profile[key]
                self.write_profile(profile)
                with self.assertRaisesRegex(ValueError, "exactly four fixed fields"):
                    self.inspect()

    def test_profile_role_artifacts_requires_string_map(self):
        original = json.loads(self.files[candidate.PROFILE_NAME])
        invalid_maps = [None, [], list(original["role_artifacts"].items()), "chain=tdend", True, 9]
        invalid_maps += [{**original["role_artifacts"], "chain": value} for value in (None, [], {}, 1, True)]
        for roles in invalid_maps:
            with self.subTest(roles=roles):
                self.write_profile({**original, "role_artifacts": roles})
                with self.assertRaisesRegex(ValueError, "must be a string map"):
                    self.inspect()

    def test_profile_requires_exact_nine_role_mapping(self):
        original = json.loads(self.files[candidate.PROFILE_NAME])
        for role in original["role_artifacts"]:
            for change in ("missing", "wrong", "path"):
                with self.subTest(role=role, change=change):
                    profile = copy.deepcopy(original)
                    if change == "missing":
                        del profile["role_artifacts"][role]
                    else:
                        profile["role_artifacts"][role] = "wrong" if change == "wrong" else "./" + profile["role_artifacts"][role]
                    self.write_profile(profile)
                    with self.assertRaisesRegex(ValueError, "fixed nine-role recipe"):
                        self.inspect()
        self.write_profile({**original, "role_artifacts": {**original["role_artifacts"], "extra": "tden-extra"}})
        with self.assertRaisesRegex(ValueError, "fixed nine-role recipe"):
            self.inspect()

    def test_profile_duplicate_nested_role_rejected(self):
        body = self.files[candidate.PROFILE_NAME].replace(b'"chain": "tdend"', b'"chain": "tdend", "chain": "tdend"')
        self.assertNotEqual(body, self.files[candidate.PROFILE_NAME])
        self.files[candidate.PROFILE_NAME] = body
        self.metadata["configuration_profile_sha256"] = candidate.sha(body)
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: chain"):
            self.inspect()

    def test_profile_field_and_role_order_not_significant(self):
        profile = dict(reversed(list(json.loads(self.files[candidate.PROFILE_NAME]).items())))
        profile["role_artifacts"] = dict(reversed(list(profile["role_artifacts"].items())))
        self.write_profile(profile)
        self.assertEqual(self.inspect()["configuration_profile_sha256"], self.metadata["configuration_profile_sha256"])

    def test_profile_roles_require_actual_archive_members(self):
        roles = json.loads(self.files[candidate.PROFILE_NAME])["role_artifacts"]
        for name in roles.values():
            with self.subTest(member=name):
                body = self.files.pop(name)
                self.write_archive()
                with self.assertRaisesRegex(ValueError, f"role artifact missing: {name}"):
                    self.inspect()
                self.files[name] = body

    def test_profile_role_members_require_manifest_coverage(self):
        roles = json.loads(self.files[candidate.PROFILE_NAME])["role_artifacts"]
        original = self.files["package.sha256"]
        for name in roles.values():
            with self.subTest(member=name):
                suffix = ("  " + name + "\n").encode()
                manifest = b"".join(line for line in original.splitlines(keepends=True) if not line.endswith(suffix))
                self.assertNotEqual(original, manifest)
                self.write_archive(bad_manifest=manifest)
                with self.assertRaisesRegex(ValueError, "member set mismatch"):
                    self.inspect()

    def test_profile_role_member_mutations_require_new_manifest_binding(self):
        roles = json.loads(self.files[candidate.PROFILE_NAME])["role_artifacts"]
        for name in roles.values():
            with self.subTest(member=name):
                before = self.inspect()
                manifest = self.files["package.sha256"]
                self.files[name] += b"changed"
                self.write_archive(bad_manifest=manifest)
                with self.assertRaisesRegex(ValueError, f"member digest mismatch: {name}"):
                    self.inspect()
                self.write_archive()
                self.assertNotEqual(before["package_manifest_sha256"], self.inspect()["package_manifest_sha256"])

    def test_metadata_version_platform_trust_mismatch_rejected(self):
        for key in ("version", "platform", "bootstrap_trust_template_sha256", "tuf_root_sha256"):
            with self.subTest(key=key):
                saved = self.metadata[key]
                self.metadata[key] = "wrong"
                self.write_archive()
                with self.assertRaises(ValueError):
                    self.inspect()
                self.metadata[key] = saved

    def test_member_mutation_rejected(self):
        manifest = self.files["package.sha256"]
        self.files[candidate.HELPER] += b"mutation"
        self.write_archive(bad_manifest=manifest)
        with self.assertRaisesRegex(ValueError, "member digest mismatch"):
            self.inspect()

    def test_duplicate_manifest_line_rejected(self):
        manifest = self.files["package.sha256"]
        self.write_archive(bad_manifest=manifest + manifest.splitlines(keepends=True)[0])
        with self.assertRaisesRegex(ValueError, "duplicate or self-referential"):
            self.inspect()

    def test_unmanifested_member_rejected(self):
        self.write_archive(extra=tarfile.TarInfo("extra"))
        with self.assertRaisesRegex(ValueError, "member set mismatch"):
            self.inspect()

    def test_multiple_members_cannot_exceed_total_unpacked_limit(self):
        limit = sum(map(len, self.files.values())) - 1
        self.assertLess(max(map(len, self.files.values())), limit)
        with patch.object(candidate, "MAX_UNPACKED_BYTES", limit):
            with self.assertRaisesRegex(ValueError, "declared total exceeds"):
                self.inspect()

    def test_declared_total_rejected_before_reading_member(self):
        member = tarfile.TarInfo("payload.bin")
        member.size = 33
        archive = MagicMock()
        archive.__enter__.return_value = archive
        archive.__iter__.return_value = iter([member])
        with patch.object(candidate, "MAX_UNPACKED_BYTES", 32), patch.object(candidate.tarfile, "open", return_value=archive):
            with self.assertRaisesRegex(ValueError, "declared total exceeds"):
                self.inspect()
        archive.extractfile.assert_not_called()

    def test_actual_read_total_has_independent_limit(self):
        member = tarfile.TarInfo("payload.bin")
        member.size = 1
        archive = MagicMock()
        archive.__enter__.return_value = archive
        archive.__iter__.return_value = iter([member])
        archive.extractfile.return_value = io.BytesIO(b"x" * 33)
        with patch.object(candidate, "MAX_UNPACKED_BYTES", 32), patch.object(candidate.tarfile, "open", return_value=archive):
            with self.assertRaisesRegex(ValueError, "actual total exceeds"):
                self.inspect()

    def test_duplicate_or_traversing_archive_member_rejected(self):
        for name in ("./package.sha256", "../outside", "/outside", "./nested/file"):
            with self.subTest(name=name):
                self.write_archive(extra=tarfile.TarInfo(name))
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_archive_link_rejected(self):
        member = tarfile.TarInfo("link")
        member.type, member.linkname = tarfile.SYMTYPE, "package.sha256"
        self.write_archive(extra=member)
        with self.assertRaisesRegex(ValueError, "non-regular"):
            self.inspect()

    def test_runtime_archive_cannot_use_legacy_claim(self):
        with self.assertRaisesRegex(ValueError, "cannot use legacy"):
            self.inspect(False)

    def test_source_revisions_are_all_bound(self):
        for key in ("chain_commit", "gateway_commit", "deploy_commit", "workflow_commit"):
            with self.subTest(key=key):
                data = self.description()
                data[key] = "9" * 40
                with self.assertRaisesRegex(ValueError, "commit mismatch|repository binding"):
                    self.check_description(data)

    def test_archive_digest_and_size_bound(self):
        for key, value in (("archive_sha256", "0" * 64), ("archive_bytes", 1)):
            data = self.description()
            data[key] = value
            with self.assertRaisesRegex(ValueError, "digest/size mismatch"):
                self.check_description(data)

    def test_missing_runtime_binding_cannot_downgrade_new_build(self):
        data = self.description()
        del data["runtime_bundle"]
        with self.assertRaisesRegex(ValueError, "downgrade/mismatch"):
            self.check_description(data)

    def test_old_run_cannot_claim_new_runtime_attestation(self):
        with self.assertRaisesRegex(ValueError, "downgrade/mismatch"):
            self.check_description(self.description(), False)

    def test_build_attempt_bound(self):
        data = self.description()
        data["workflow_run_attempt"] = "1"
        with self.assertRaisesRegex(ValueError, "attempt mismatch"):
            self.check_description(data)

    def test_job_step_requires_success_and_no_duplicates(self):
        step = {"name": candidate.DESCRIPTION_STEP, "conclusion": "success"}
        self.assertFalse(candidate.needs_runtime([{"jobs": []}]))
        self.assertTrue(candidate.needs_runtime([{"jobs": []}, {"jobs": [{"steps": [step]}]}]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            candidate.needs_runtime([{"jobs": [{"steps": [step, step]}]}])
        step["conclusion"] = "skipped"
        with self.assertRaisesRegex(ValueError, "did not succeed"):
            candidate.needs_runtime([{"jobs": [{"steps": [step]}]}])

    def test_receipt_requires_exact_subject_commit_attempt_and_hosted_runner(self):
        receipt = self.receipt(candidate.ARCHIVE, "a" * 64)
        candidate.validate_receipt(receipt, candidate.ARCHIVE, "a" * 64, self.run, self.repo)
        for field in ("runInvocationURI", "sourceRepositoryDigest", "buildSignerDigest", "runnerEnvironment", "buildSignerURI", "issuer"):
            with self.subTest(field=field):
                changed = copy.deepcopy(receipt)
                changed[0]["verificationResult"]["signature"]["certificate"][field] = "wrong"
                with self.assertRaises(ValueError):
                    candidate.validate_receipt(changed, candidate.ARCHIVE, "a" * 64, self.run, self.repo)
        with self.assertRaisesRegex(ValueError, "subject mismatch"):
            candidate.validate_receipt(receipt, "candidate-build.json", "b" * 64, self.run, self.repo)

    def test_matching_digest_other_attempt_is_not_proof(self):
        receipt = self.receipt(candidate.ARCHIVE, "a" * 64)
        self.run["run_attempt"] += 1
        with self.assertRaisesRegex(ValueError, "exact candidate run/attempt"):
            candidate.validate_receipt(receipt, candidate.ARCHIVE, "a" * 64, self.run, self.repo)

    def helper_info(self):
        return {
            "Path": "github.com/tden/tden-gateway/cmd/node-runtime-upgrade", "GoVersion": "go1.26.7",
            "Settings": [{"Key": key, "Value": value} for key, value in {
                "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "vcs": "git",
                "vcs.revision": "2" * 40, "vcs.modified": "false",
            }.items()],
        }

    def test_helper_go_metadata_exact_gateway_and_clean_build(self):
        candidate.validate_helper_build(self.helper_info(), "2" * 40)
        for field in ("GOOS", "GOARCH", "CGO_ENABLED", "vcs.revision", "vcs.modified"):
            with self.subTest(field=field):
                info = self.helper_info()
                next(item for item in info["Settings"] if item["Key"] == field)["Value"] = "wrong"
                with self.assertRaises(ValueError):
                    candidate.validate_helper_build(info, "2" * 40)

    def test_helper_command_and_toolchain_must_match(self):
        for key, value in (("Path", "github.com/tden/tden-gateway/cmd/gateway"), ("GoVersion", "go1.25.0")):
            info = self.helper_info()
            info[key] = value
            with self.assertRaises(ValueError):
                candidate.validate_helper_build(info, "2" * 40)

    def prepare_create(self):
        source = self.root / "source"
        profile = source / "deploy/node-installer/configuration-profile.json"
        profile.parent.mkdir(parents=True)
        profile.write_bytes(self.files["configuration-profile.json"])
        (self.root / candidate.HELPER).write_bytes(self.files[candidate.HELPER])
        (self.root / "policy.json").write_text(json.dumps(self.policy))
        args = SimpleNamespace(directory=self.root, package_directory=self.root, source_root=source, policy=self.root / "policy.json")
        return args, profile

    def test_create_binds_fixed_source_profile_and_does_not_execute_helper(self):
        args, profile = self.prepare_create()
        refs = {"tden-chain": "1" * 40, "tden-gateway": "2" * 40, "deploy": "3" * 40}

        def command(argv, **kwargs):
            if argv[:4] == ["go", "version", "-m", "-json"]:
                return json.dumps(self.helper_info()).encode()
            self.assertEqual(argv[0], "git")
            return "" if argv[3] == "status" else refs[Path(argv[2]).name]

        env = {"GITHUB_REPOSITORY": self.repo, "GITHUB_RUN_ID": str(self.run["id"]), "GITHUB_RUN_ATTEMPT": str(self.run["run_attempt"]), "GITHUB_SHA": self.run["head_sha"], "CANDIDATE_VERSION": self.version}
        with patch.dict(os.environ, env), patch.object(candidate.subprocess, "check_output", side_effect=command), patch("builtins.print"):
            candidate.create(args)
            self.check_description(candidate.read_json(self.root / "candidate-build.json"))
            profile.write_bytes(b"changed source profile")
            with self.assertRaisesRegex(ValueError, "checked-out fixed"):
                candidate.create(args)

    def test_verify_requires_both_receipts_and_original_runtime_bytes(self):
        data = self.description()
        self.write_json("candidate-build.json", data)
        self.write_json("policy.json", self.policy)
        self.write_json("run.json", self.run)
        self.write_json("jobs.json", [{"jobs": [{"steps": [{"name": candidate.DESCRIPTION_STEP, "conclusion": "success"}]}]}])
        self.write_json("archive-receipt.json", self.receipt(candidate.ARCHIVE, data["archive_sha256"]))
        self.write_json("description-receipt.json", self.receipt("candidate-build.json", candidate.file_sha(self.root / "candidate-build.json")))
        args = SimpleNamespace(directory=self.root, policy=self.root / "policy.json", run=self.root / "run.json", jobs=self.root / "jobs.json", archive_receipt=self.root / "archive-receipt.json", description_receipt=self.root / "description-receipt.json")
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": self.repo, "EXPECTED_SHA256": data["archive_sha256"]}), patch("builtins.print"):
            candidate.verify(args)
            original = copy.deepcopy(data)
            data["gateway_commit"] = "9" * 40
            data["source_repositories"] = candidate.source_repositories(data)
            self.write_json("candidate-build.json", data)
            with self.assertRaisesRegex(ValueError, "subject mismatch"):
                candidate.verify(args)
            data = original
            self.write_json("candidate-build.json", data)
            self.write_json("description-receipt.json", [])
            with self.assertRaisesRegex(ValueError, "no verified attestation"):
                candidate.verify(args)
            data["runtime_bundle"]["package_manifest_sha256"] = "0" * 64
            self.write_json("candidate-build.json", data)
            with self.assertRaisesRegex(ValueError, "differs from original archive"):
                candidate.verify(args)

    def write_json(self, name, data):
        (self.root / name).write_text(json.dumps(data), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
