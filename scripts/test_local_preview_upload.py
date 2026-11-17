import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("upload", Path(__file__).with_name("local_preview_upload.py"))
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tden-upload-test-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "tden-node-linux-amd64.tar.gz"
        self.content = b"synthetic package bytes\x00\xff"
        self.path.write_bytes(self.content)
        self.sha = hashlib.sha256(self.content).hexdigest()
        self.token = b"synthetic_github_token_00000000000000000000"
        self.calls = []

    def run_upload(self, runner=None, **overrides):
        args = dict(release_id=448592664, filename=str(self.path), name=self.path.name,
                    expected_bytes=len(self.content), expected_sha256=self.sha, token=self.token,
                    runner=runner or self.success)
        args.update(overrides)
        return U.upload(**args)

    def result(self, status=201, **changes):
        body = dict(id=123, name=self.path.name, state="uploaded", size=len(self.content), digest="sha256:" + self.sha)
        body.update(changes)
        return subprocess.CompletedProcess([], 0, json.dumps(body).encode() +
            f"\nTDEN_UPLOAD_STATUS={status} {len(self.content)} 1.234567 0 2\n".encode(), b"")

    def success(self, args, **kwargs):
        self.calls.append((args, kwargs))
        fd = kwargs["pass_fds"][0]
        self.assertEqual(args[args.index("--data-binary") + 1], f"@/proc/self/fd/{fd}")
        self.assertEqual(os.read(fd, 1000), self.content)
        return self.result()

    def test_real_file_upload_is_bound_and_auth_stays_in_stdin(self):
        result = self.run_upload()
        args, kw = self.calls[0]
        self.assertTrue(result["ok"])
        self.assertEqual(result["sha256"], self.sha)
        self.assertEqual(args[:2], ["/usr/bin/curl", "-q"])
        self.assertEqual(args[args.index("--retry") + 1], "0")
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertEqual(args[args.index("--url") + 1],
            "https://uploads.github.com/repos/sunbird84/tden-node-releases/releases/448592664/assets?name=" + self.path.name)
        self.assertNotIn("--location", args)
        self.assertNotIn("--insecure", args)
        self.assertEqual(kw["input"], b'header = "Authorization: Bearer ' + self.token + b'"\n')
        self.assertNotIn(self.token.decode(), repr(args) + repr(kw["env"]) + repr(result))
        self.assertEqual(kw["timeout"], 850)

    def test_bad_file_or_digest_never_calls_curl(self):
        for overrides in [{"expected_sha256": "0" * 64}, {"expected_bytes": len(self.content) + 1},
                          {"name": "other"}, {"release_id": True}, {"token": self.token + b'"\nurl=bad'}]:
            with self.subTest(overrides=list(overrides)), self.assertRaises(U.UploadError):
                self.run_upload(**overrides)
        self.assertEqual(self.calls, [])

    def test_symlink_and_multiple_links_are_rejected(self):
        other = self.path.with_name("other")
        self.path.rename(other)
        self.path.symlink_to(other)
        with self.assertRaises(U.UploadError):
            self.run_upload()
        self.path.unlink()
        os.link(other, self.path)
        with self.assertRaises(U.UploadError):
            self.run_upload()
        self.assertEqual(self.calls, [])

    def test_mutation_or_path_replacement_during_transfer_is_rejected(self):
        def mutate(args, **kwargs):
            self.path.write_bytes(b"changed")
            return self.result()
        with self.assertRaisesRegex(U.UploadError, "ASSET_CHANGED"):
            self.run_upload(runner=mutate)
        self.path.write_bytes(self.content)
        def replace(args, **kwargs):
            self.path.unlink()
            self.path.write_bytes(self.content)
            return self.result()
        with self.assertRaisesRegex(U.UploadError, "ASSET_CHANGED"):
            self.run_upload(runner=replace)

    def test_redirect_or_network_error_has_closed_diagnostics(self):
        for status in [302, 401, 502]:
            with self.subTest(status=status), self.assertRaises(U.UploadError) as raised:
                self.run_upload(runner=lambda *a, **k: self.result(status=status))
            self.assertEqual(raised.exception.code, "TRANSFER_FAILED")
            self.assertEqual(raised.exception.diagnostics["http_status"], status)
        def fail(*a, **k):
            return subprocess.CompletedProcess([], 35, b"private response " + self.token,
                                               b"private stderr " + self.token)
        with self.assertRaises(U.UploadError) as raised:
            self.run_upload(runner=fail)
        self.assertNotIn(self.token.decode(), repr(raised.exception.diagnostics))
        self.assertEqual(raised.exception.diagnostics["curl_exit"], 35)

    def test_wrong_asset_response_is_rejected(self):
        for change in [{"name": "other"}, {"state": "starter"}, {"size": False}, {"id": True}, {"digest": None}]:
            with self.subTest(change=change), self.assertRaisesRegex(U.UploadError, "RESPONSE_BINDING"):
                self.run_upload(runner=lambda *a, **k: self.result(**change))

    def test_failure_before_http_retains_zero_version_diagnostics(self):
        def fail(*a, **k):
            return subprocess.CompletedProcess([], 35, b"\nTDEN_UPLOAD_STATUS=000 0 15.123456 20 0\n", b"TLS failed")
        with self.assertRaises(U.UploadError) as raised:
            self.run_upload(runner=fail)
        self.assertEqual(raised.exception.diagnostics["http_status"], 0)
        self.assertEqual(raised.exception.diagnostics["http_version"], "0")
        self.assertEqual(raised.exception.diagnostics["tls_verify"], 20)

    def test_timeout_does_not_echo_subprocess_input(self):
        def timeout(*a, **k):
            raise subprocess.TimeoutExpired(self.token.decode(), 850, stderr=self.token)
        with self.assertRaises(U.UploadError) as raised:
            self.run_upload(runner=timeout)
        self.assertEqual(raised.exception.code, "PROCESS_TIMEOUT")
        self.assertNotIn(self.token.decode(), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
