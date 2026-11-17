"""Local verifier tests: real files, Git trees and gzip; Go metadata is a test double."""

import copy
import gzip
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_candidate_metadata as local


VERSION = "0.12.0-test.20261117.1"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def binding(path):
    return {"path": str(path), "sha256": local.file_sha(path)}


def records(files):
    return [{"name": name, "bytes": len(body), "sha256": local.digest(body)}
            for name, body in sorted(files.items())]


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.mode, info.size = 0o755, len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def package(version, helper):
    files = {name: b"fixture\n" for name in local.MEMBERS}
    files["node-runtime-files.py"] = helper
    files["bootstrap-trust-template.json"] = b'{"bootstrap":"fixture"}\n'
    files["tuf-root.json"] = b'{"root":"fixture"}\n'
    policy = {key: local.digest(files[name]) for key, name in local.hosted.ROOT_FILES.items()}
    files[local.hosted.PROFILE_NAME] = local.canonical({**local.hosted.PROFILE_FIELDS,
                                                      "role_artifacts": local.hosted.PROFILE_ROLE_ARTIFACTS})
    files["tden-node-runtime-upgrade"] = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00"
    files["package-metadata.json"] = local.canonical({
        "protocol": "tden:node-runtime-package:v2", "version": version, "platform": "linux-amd64",
        **policy, "configuration_profile_sha256": local.digest(files[local.hosted.PROFILE_NAME])})
    files["package-version.txt"] = (version + "\n").encode()
    files["package.sha256"] = b"".join((local.digest(body) + "  " + name + "\n").encode()
                                         for name, body in sorted(files.items()) if name != "package.sha256")
    return files, policy


class Fixture:
    def __init__(self, root):
        self.root = root
        self.files, policy = package(VERSION, b"# new terminal recovery helper\n")
        old, _ = package("0.12.0-test.20261114.3", b"# original helper\n")
        self.go = write(root / "tools/go", b"fixture Go metadata observer\n")
        self.pwsh = write(root / "tools/pwsh", b"fixture PowerShell\n")
        self.pins = {"go": (str(self.go), local.file_sha(self.go)),
                     "powershell": (str(self.pwsh), local.file_sha(self.pwsh))}
        self.control = root / "control"
        for name in ("local_candidate_metadata.py", "candidate_metadata.py"):
            write(self.control / "scripts" / name, (local.SCRIPT_ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
        self.policy = write(self.control / "release-policy.json", local.canonical(policy))
        self.control_ref = self.repo(self.control)
        self.sources = {}
        for name in local.REPOSITORIES:
            path = root / "sources" / name
            write(path / "README", b"fixture source\n")
            if name == "deploy":
                installer = path / "node-installer"
                for file in ("node-runtime-files.py", local.hosted.PROFILE_NAME):
                    write(installer / file, self.files[file])
                for file in ("build-node-package.ps1", "archive-node-package.py"):
                    write(installer / file, b"fixture build recipe\n")
            self.sources[name] = self.repo(path)
        self.archive = write(root / "build" / local.ARCHIVE, gzip.compress(tar_bytes(self.files), mtime=0))
        for name, body in self.files.items():
            write(self.archive.parent / "package" / name, body)
        self.baseline = write(root / "baseline" / "receipt.json", local.canonical({"buildAccepted": True, "files": records(old)}))
        write(self.baseline.parent / "package-metadata.json", old["package-metadata.json"])
        steps = []
        for index, name in enumerate(("whole-package", "vcs-tdend", "vcs-tden-gateway", "capability", "archive", "bootstrap-preflight"), 1):
            log = write(root / "logs" / (name + ".log"), b"fixture successful observation\n")
            steps.append({"name": name, "startedAtUTC": f"2026-11-17T00:0{index}:00Z",
                          "finishedAtUTC": f"2026-11-17T00:0{index}:01Z", "exitCode": 0,
                          "log": str(log), "logSHA256": local.file_sha(log)})
        receipt = {"protocol": "tden:terminal-sync-recovery-local-node-build:v1", "version": VERSION,
                   "startedAtUTC": "2026-11-17T00:00:00Z", "finishedAtUTC": "2026-11-17T00:08:00Z",
                   "sourceCommits": {name: ref["commit"] for name, ref in self.sources.items()},
                   "sources": {name: {**ref, "tree": self.git(ref["path"], "rev-parse", "HEAD^{tree}")}
                               for name, ref in self.sources.items()},
                   "baseline": binding(self.baseline), "archive": {**binding(self.archive), "bytes": self.archive.stat().st_size},
                   "buildAccepted": True, "allSourceCheckoutsClean": True, "originalVerifierAccepted": True,
                   "networkNamespaceIsolated": True, "officialProvenance": False, "published": False,
                   "deployed": False, "cloudMutation": False, "steps": steps, "files": records(self.files),
                   "internalManifestSHA256": local.digest(self.files["package.sha256"]),
                   "changedPackageMembers": sorted(local.CHANGED)}
        self.receipt = write(root / "receipt.json", local.canonical(receipt))
        driver = b"\n".join(("need(sha(" + variable + ")==\'" + self.pins[name][1] + "\', 'pin')").encode()
                             for name, variable in (("go", "go"), ("powershell", "pwsh")))
        self.request = {"protocol": local.REQUEST_PROTOCOL, "version": VERSION, "archive": receipt["archive"],
                        "build_receipt": binding(self.receipt), "baseline_receipt": binding(self.baseline),
                        "control": self.control_ref, "sources": self.sources,
                        "tools": {"go": binding(self.go), "powershell": binding(self.pwsh),
                                  "python": binding(Path(sys.executable).resolve()), "git": binding(Path("/usr/bin/git").resolve())},
                        "scripts": {"build_driver": binding(write(root / "driver.py", driver)),
                                    "bootstrap_preflight": binding(write(root / "preflight.py", b"fixture preflight\n"))},
                        "policy": binding(self.policy)}
        self.request_path = write(root / "request.json", local.canonical(self.request))
        self.assets = root / "assets"
        self.assets.mkdir()
        shutil.copyfile(self.archive, self.assets / local.ARCHIVE)
        write(self.assets / (local.ARCHIVE + ".sha256"), (self.request["archive"]["sha256"] + "  " + local.ARCHIVE + "\n").encode())

    @staticmethod
    def git(path, *args):
        return subprocess.check_output(["/usr/bin/git", "-C", str(path), *args], stderr=subprocess.DEVNULL).decode().strip()

    def repo(self, path):
        self.git(path, "init", "--quiet")
        self.git(path, "add", ".")
        self.git(path, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture")
        return {"path": str(path), "commit": self.git(path, "rev-parse", "HEAD")}

    def description(self):
        with mock.patch.object(local, "PINNED_BUILD_TOOLS", self.pins), mock.patch.object(local, "go_vcs"):
            return local.candidate(local.load_request(self.request_path))


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tden-local-metadata-test-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))
        self.pins = mock.patch.object(local, "PINNED_BUILD_TOOLS", self.f.pins)
        self.pins.start()
        self.addCleanup(self.pins.stop)
        self.vcs = mock.patch.object(local, "go_vcs")
        self.vcs.start()
        self.addCleanup(self.vcs.stop)

    def test_complete_local_descriptor_and_exact_assets(self):
        description = self.f.description()
        write(self.f.assets / "candidate-build.json", local.canonical(description))
        result = local.verify(self.f.request, self.f.assets)
        self.assertEqual(set(result), {"protocol", "tag", "control_commit", "archive_sha256", "version", "assets"})
        self.assertEqual(result["protocol"], local.VERIFICATION_PROTOCOL)
        self.assertEqual({row["name"] for row in result["assets"]}, local.ASSETS)
        self.assertEqual(description["build_environment"], "local")
        self.assertEqual(description["local_build_provenance"]["build_tools_observation"], "build_driver_pinned_reverified")
        text = local.canonical(description).decode()
        for forbidden in (str(self.f.root), "workflow", "attestation", "run_id"):
            self.assertNotIn(forbidden, text)

    def test_wrong_archive_hash_rejected(self):
        self.f.request["archive"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            local.candidate(self.f.request)

    def test_dirty_source_rejected(self):
        write(Path(self.f.sources["tden-chain"]["path"]) / "untracked", b"dirty")
        with self.assertRaisesRegex(ValueError, "dirty source"):
            local.candidate(self.f.request)

    def test_unpinned_git_and_go_rejected(self):
        for name in ("git", "go"):
            with self.subTest(name=name):
                request = copy.deepcopy(self.f.request)
                request["tools"][name] = binding(write(self.f.root / ("fake-" + name), b"#!/bin/sh\nexit 0\n"))
                with self.assertRaises(ValueError):
                    local.candidate(request)

    def test_mixed_hosted_fields_rejected(self):
        description = self.f.description()
        description["workflow_run_id"] = "43597337323"
        write(self.f.assets / "candidate-build.json", local.canonical(description))
        with self.assertRaisesRegex(ValueError, "descriptor differs"):
            local.verify(self.f.request, self.f.assets)

    def test_extra_asset_rejected(self):
        write(self.f.assets / "candidate-build.json", b"{}")
        write(self.f.assets / "unexpected", b"x")
        with self.assertRaisesRegex(ValueError, "three-asset"):
            local.verify(self.f.request, self.f.assets)

    def test_bound_decoded_receipt_rejects_second_read_change(self):
        original = local.bounded_bytes
        def raced(path, *args):
            if Path(path) == self.f.receipt:
                return b'{"buildAccepted":false}\n'
            return original(path, *args)
        with mock.patch.object(local, "bounded_bytes", side_effect=raced), self.assertRaisesRegex(ValueError, "changed before decoding"):
            local.candidate(self.f.request)

    def test_source_copy_allows_only_crlf_change(self):
        path = self.f.control / "scripts/candidate_metadata.py"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        self.f.control_ref.update(self.f.repo(self.f.control))
        local.candidate(self.f.request)
        path.write_bytes(path.read_bytes() + b"# changed code\n")
        self.f.control_ref.update(self.f.repo(self.f.control))
        with self.assertRaisesRegex(ValueError, "executing verifier differs"):
            local.candidate(self.f.request)

    def test_manifest_and_local_package_member_tamper_rejected(self):
        write(self.f.archive.parent / "package/tdend", b"substituted")
        with self.assertRaisesRegex(ValueError, "local package member differs"):
            local.candidate(self.f.request)

    def test_request_stable_unknown_and_duplicate_rejected(self):
        for change in ({"version": "0.12.0"}, {"workflow_run_id": "1"}):
            write(self.f.request_path, local.canonical({**self.f.request, **change}))
            with self.assertRaises(ValueError):
                local.load_request(self.f.request_path)
        write(self.f.request_path, b'{"protocol":1,"protocol":2}')
        with self.assertRaises(ValueError):
            local.load_request(self.f.request_path)


class ArchiveAndVcsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tden-local-archive-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / local.ARCHIVE
        self.files, _ = package(VERSION, b"helper")
        self.raw = tar_bytes(self.files)

    def test_complete_gzip_crc_and_tail(self):
        good = gzip.compress(self.raw, mtime=0)
        write(self.path, good)
        self.assertEqual(set(local.archive_members(self.path)[0]), local.MEMBERS)
        bad_crc = good[:-8] + bytes([good[-8] ^ 1]) + good[-7:]
        for body in (bad_crc, good[:-1], good + b"trailing garbage", gzip.compress(self.raw + b"x"),
                     gzip.compress(self.raw + bytes(65537))):
            with self.subTest(length=len(body)):
                write(self.path, body)
                with self.assertRaises((ValueError, OSError, EOFError)):
                    local.archive_members(self.path)

    def test_member_closure_and_decode_bound(self):
        write(self.path, gzip.compress(tar_bytes({**self.files, "surprise": b"x"})))
        with self.assertRaises(ValueError):
            local.archive_members(self.path)
        write(self.path, gzip.compress(self.raw))
        with mock.patch.object(local, "MAX_DECODED", len(self.raw) - 1), self.assertRaises(ValueError):
            local.archive_members(self.path)

    def test_symlink_archive_rejected(self):
        target = write(self.path.with_suffix(".target"), gzip.compress(self.raw))
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            local.archive_members(self.path)

    def test_go_metadata_requires_clean_exact_revision(self):
        commit = "a" * 40
        values = {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "vcs": "git",
                  "vcs.revision": commit, "vcs.modified": "false"}
        info = {"Path": "github.com/tden/tden-chain/cmd/tdend", "GoVersion": "go1.26.7",
                "Settings": [{"Key": key, "Value": value} for key, value in values.items()]}
        with mock.patch.object(local, "command", return_value=local.canonical(info)):
            local.go_vcs("go", "tdend", commit, info["Path"])
        for key, wrong in (("vcs.modified", "true"), ("vcs.revision", "b" * 40), ("CGO_ENABLED", "1")):
            bad = copy.deepcopy(info)
            next(row for row in bad["Settings"] if row["Key"] == key)["Value"] = wrong
            with mock.patch.object(local, "command", return_value=local.canonical(bad)), self.assertRaises(ValueError):
                local.go_vcs("go", "tdend", commit, info["Path"])

    def test_cli_reports_only_static_error_code(self):
        request = write(Path(self.temp.name) / "sensitive-path.json", b"bad JSON")
        result = subprocess.run([sys.executable, "-I", "-B", str(local.SCRIPT_ROOT / "local_candidate_metadata.py"),
                                 "verify", "--request", str(request), "--asset-dir", str(self.path.parent)], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"LOCAL_CANDIDATE_REQUEST\n")


if __name__ == "__main__":
    unittest.main()
