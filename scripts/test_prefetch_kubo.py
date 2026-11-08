import contextlib
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import prefetch_kubo as kubo


class Response(io.BytesIO):
    def __init__(self, body=b"", status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}


class KuboAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch("socket.socket", side_effect=AssertionError("offline test")))
        self.stack.enter_context(mock.patch("socket.getaddrinfo", side_effect=AssertionError("offline test")))
        root = os.environ.get("TDEN_TEST_TEMP_ROOT")
        self.tmp = self.stack.enter_context(tempfile.TemporaryDirectory(dir=root, prefix="kubo-unit-"))
        self.root = Path(self.tmp).resolve()
        self.data = b"synthetic-pinned-archive"
        self.stack.enter_context(mock.patch.object(kubo, "EXPECTED_SIZE", len(self.data)))
        self.stack.enter_context(mock.patch.object(kubo, "EXPECTED_SHA256", hashlib.sha256(self.data).hexdigest()))
        self.stack.enter_context(mock.patch.object(kubo, "EXPECTED_SHA512", hashlib.sha512(self.data).hexdigest()))

    def fetch(self, responses, clock=lambda: 0):
        self.requests = []
        iterator = iter(responses)

        def transport(url, headers, timeout):
            self.requests.append((url, headers, timeout))
            return next(iterator)

        return kubo.acquire(self.root, "123", "1", "unit-token", transport, clock)

    def test_fixed_production_contract(self):
        self.assertEqual(kubo.API_URL, "https://api.github.com/repos/ipfs/kubo/releases/assets/441662929")
        self.assertEqual(kubo.MAX_REDIRECTS, 3)
        self.assertEqual(kubo.MAX_SECONDS, 180)

    def test_valid_direct_archive(self):
        receipt = self.fetch([Response(self.data, headers={"Content-Length": str(len(self.data))})])
        self.assertEqual(Path(receipt["archive"]).read_bytes(), self.data)
        self.assertEqual(receipt["bytes"], len(self.data))
        self.assertEqual(self.requests[0][1]["Authorization"], "Bearer unit-token")

    def test_redirect_drops_auth_and_does_not_report_signed_url(self):
        url = "https://release-assets.githubusercontent.com/github-production-release-asset/21233191/asset-id?signature=unit-secret"
        receipt = self.fetch([Response(status=302, headers={"Location": url}), Response(self.data)])
        self.assertNotIn("Authorization", self.requests[1][1])
        self.assertNotIn("unit-secret", str(receipt))
        self.assertNotIn("unit-token", str(receipt))

    def test_unsafe_redirects(self):
        for url in ("http://github.com" + kubo.DOWNLOAD_PATH,
                    "https://user:pass@github.com" + kubo.DOWNLOAD_PATH,
                    "https://example.com/asset", "https://github.com:444" + kubo.DOWNLOAD_PATH,
                    "https://release-assets.githubusercontent.com/github-production-release-asset/1/asset",
                    kubo.API_URL + "?token=secret", kubo.API_URL + "#fragment"):
            with self.subTest(case=url.split(":", 1)[0]):
                with self.assertRaisesRegex(kubo.AcquisitionError, "redirect-policy"):
                    kubo.validate_url(url)

    def test_redirect_loop_is_bounded(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "redirect-limit"):
            self.fetch([Response(status=302, headers={"Location": kubo.API_URL}) for _ in range(4)])
        self.assertEqual(len(self.requests), 4)

    def test_declared_size_rejected(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "declared-size"):
            self.fetch([Response(self.data, headers={"Content-Length": "1"})])

    def test_truncation_rejected(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "received-size"):
            self.fetch([Response(self.data[:-1])])

    def test_oversize_rejected_before_extra_write(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "received-size"):
            self.fetch([Response(self.data + b"extra")])
        target = self.root / "tden-kubo-123-1" / kubo.ARCHIVE_NAME
        self.assertLessEqual(target.stat().st_size, len(self.data))

    def test_sha256_rejected(self):
        with mock.patch.object(kubo, "EXPECTED_SHA256", "0" * 64):
            with self.assertRaisesRegex(kubo.AcquisitionError, "digest"):
                self.fetch([Response(self.data)])

    def test_sha512_rejected(self):
        with mock.patch.object(kubo, "EXPECTED_SHA512", "0" * 128):
            with self.assertRaisesRegex(kubo.AcquisitionError, "digest"):
                self.fetch([Response(self.data)])

    def test_existing_directory_rejected_without_clobber(self):
        directory = self.root / "tden-kubo-123-1"
        directory.mkdir()
        marker = directory / "preserve"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.fetch([Response(self.data)])
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.assertEqual(self.requests, [])

    def test_symlink_root_rejected(self):
        linked = self.root / "linked"
        try:
            linked.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            if sys.platform == "linux":
                raise
            self.skipTest("host cannot create test symlinks")
        with self.assertRaisesRegex(kubo.AcquisitionError, "temporary-root"):
            kubo.fresh_directory(linked, "123", "1")

    def test_deadline_rejected_before_network(self):
        values = iter([0, 181])
        with self.assertRaisesRegex(kubo.AcquisitionError, "deadline"):
            self.fetch([], lambda: next(values))
        self.assertEqual(self.requests, [])

    def test_json_response_rejected(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "non-archive-response"):
            self.fetch([Response(b"{}", headers={"Content-Type": "application/json"})])

    def test_deadline_during_stream_leaves_no_receipt(self):
        values = iter([0, 0, 0, 181])
        with self.assertRaisesRegex(kubo.AcquisitionError, "deadline"):
            self.fetch([Response(self.data)], lambda: next(values))

    def test_no_redirect_adapter_wiring(self):
        response = Response(self.data)
        with mock.patch.object(kubo.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            self.assertIs(kubo.open_remote(kubo.API_URL, {"Accept": "application/octet-stream"}, 3), response)
            handler = build.call_args.args[0]
            self.assertIsInstance(handler, kubo.NoRedirect)
            self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, kubo.API_URL))
            request = build.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, kubo.API_URL)
            self.assertEqual(build.return_value.open.call_args.kwargs, {"timeout": 3})

    def test_http_error_adapter_returns_response_for_policy_checks(self):
        response = kubo.urllib.error.HTTPError(kubo.API_URL, 302, "redirect", {}, io.BytesIO())
        with mock.patch.object(kubo.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = response
            self.assertIs(kubo.open_remote(kubo.API_URL, {}, 3), response)
        response.close()

    def test_main_failure_redaction_alarm_reset_and_output_suppression(self):
        for error, label in ((OSError("signed-url-secret-token"), "transport-or-local-io"),
                             (kubo.AcquisitionError("deadline"), "deadline")):
            with self.subTest(code=label), contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(kubo.sys, "platform", "linux"))
                stack.enter_context(mock.patch.dict(os.environ, {
                    "GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(self.root),
                    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_TOKEN": "unit-secret-token", "GITHUB_OUTPUT": str(self.root / "output"),
                }))
                stack.enter_context(mock.patch.object(kubo.signal, "SIGALRM", 14, create=True))
                stack.enter_context(mock.patch.object(kubo.signal, "ITIMER_REAL", 0, create=True))
                install = stack.enter_context(mock.patch.object(kubo.signal, "signal"))
                timer = stack.enter_context(mock.patch.object(kubo.signal, "setitimer", create=True))
                stack.enter_context(mock.patch.object(kubo, "acquire", side_effect=error))
                publish = stack.enter_context(mock.patch.object(kubo, "publish_output"))
                stdout, stderr = io.StringIO(), io.StringIO()
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                self.assertEqual(kubo.main(), 1)
                publish.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "Pinned Kubo acquisition failed: " + label + "\n")
                self.assertEqual(timer.call_args_list, [mock.call(0, 180), mock.call(0, 0)])
                with self.assertRaisesRegex(kubo.AcquisitionError, "deadline"):
                    install.call_args.args[1](14, None)

    def test_wrong_status_rejected(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "http-status"):
            self.fetch([Response(status=403)])

    def test_invalid_run_identity_rejected(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "run-identity"):
            kubo.fresh_directory(self.root, "../old", "1")

    def test_missing_token_rejected(self):
        with self.assertRaisesRegex(kubo.AcquisitionError, "token-unavailable"):
            kubo.acquire(self.root, "123", "1", "")

    def test_publish_only_accepted_path(self):
        receipt = self.fetch([Response(self.data)])
        output = self.root / "github-output"
        output.touch()
        kubo.publish_output(receipt, output)
        self.assertEqual(output.read_text(), "archive=" + receipt["archive"] + "\n")


class FixedContractTests(unittest.TestCase):
    def test_production_pins_are_unchanged(self):
        self.assertEqual(kubo.EXPECTED_SIZE, 54571642)
        self.assertEqual(kubo.EXPECTED_SHA256, "284145534168b51fe980f73c90f0ce84b55ca293034836b2ba8ea8f93435116e")
        self.assertEqual(kubo.EXPECTED_SHA512, "054c38a0cf66f7d738e25085ad62cb3a42d03d4bac329b7dd25c1d71cf18e1ce87d55b1d1b705b04c65210dca9109973579e0eb1cd72f6341ecb3311d840d156")


if __name__ == "__main__":
    unittest.main()
