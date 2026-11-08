from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_bootstrap_fixture_dates as dates


class FixtureDateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "manifest.json"
        self.now = 2_000_000_000
        self.valid = {"issued_at_unix": self.now - 10, "expires_at_unix": self.now + 100}

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def rejected(self, data, reason):
        with self.assertRaisesRegex(dates.FixtureDateError, "^" + reason + "$"):
            dates.check_dates(data, self.now)

    def test_current_window_only_passes_date_check(self):
        dates.check_dates(self.valid, self.now)

    def test_expired_and_equal_now_rejected(self):
        for expiry in (self.now - 1, self.now):
            self.rejected({**self.valid, "expires_at_unix": expiry}, "expired")

    def test_future_issue_clock_skew_boundary(self):
        dates.check_dates({"issued_at_unix": self.now + 600, "expires_at_unix": self.now + 700}, self.now)
        self.rejected({"issued_at_unix": self.now + 601, "expires_at_unix": self.now + 700}, "future-issued")

    def test_maximum_lifetime_boundary(self):
        dates.check_dates({"issued_at_unix": self.now, "expires_at_unix": self.now + dates.MAX_AGE_SECONDS}, self.now)
        self.rejected({"issued_at_unix": self.now, "expires_at_unix": self.now + dates.MAX_AGE_SECONDS + 1}, "excess-lifetime")

    def test_inverted_and_equal_window(self):
        for expiry in (self.now + 9, self.now + 10):
            self.rejected({"issued_at_unix": self.now + 10, "expires_at_unix": expiry}, "inverted-window")

    def test_json_integer_types_and_int64_bounds(self):
        for value in (None, True, False, "SENSITIVE_DATE", 1.5, 2**63, -(2**63)-1):
            for field in ("issued_at_unix", "expires_at_unix"):
                self.rejected({**self.valid, field: value}, "invalid-date-fields")

    def test_shape_missing_fields_and_clock(self):
        for data in ([], "SENSITIVE_VALUE", None):
            self.rejected(data, "invalid-shape")
        self.rejected({}, "invalid-date-fields")
        for now in (0, -1, True, 1.5):
            with self.assertRaisesRegex(dates.FixtureDateError, "^clock-unavailable$"):
                dates.check_dates(self.valid, now)

    def test_public_file_passes_without_executing_or_using_signatures(self):
        self.write({**self.valid, "signatures": [{"key_id": "synthetic-not-authority"}]})
        dates.check_file(self.path, self.now)

    def test_duplicate_fields_rejected_without_name(self):
        self.path.write_text('{"SENSITIVE_KEY":1,"SENSITIVE_KEY":2}', encoding="utf-8")
        with self.assertRaisesRegex(dates.FixtureDateError, "^duplicate-fields$"):
            dates.check_file(self.path, self.now)

    def test_invalid_json_utf8_and_empty_input(self):
        for body, reason in ((b"{SENSITIVE_BODY", "invalid-json"), (b"\xff", "invalid-json"), (b"", "invalid-size")):
            self.path.write_bytes(body)
            with self.assertRaisesRegex(dates.FixtureDateError, "^" + reason + "$"):
                dates.check_file(self.path, self.now)

    def test_size_limit(self):
        self.path.write_bytes(b" " * (dates.MAX_BYTES + 1))
        with self.assertRaisesRegex(dates.FixtureDateError, "^invalid-size$"):
            dates.check_file(self.path, self.now)

    def test_missing_path_redacted(self):
        with self.assertRaisesRegex(dates.FixtureDateError, "^read-failed$"):
            dates.check_file(self.root / "SENSITIVE_MISSING_PATH", self.now)

    def test_directory_rejected(self):
        with self.assertRaisesRegex(dates.FixtureDateError, "^non-regular-file$"):
            dates.check_file(self.root, self.now)

    def test_symlink_rejected(self):
        self.write(self.valid)
        link = self.root / "link"
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                raise
            self.skipTest("Windows symlink capability unavailable")
        with self.assertRaisesRegex(dates.FixtureDateError, "^non-regular-file$"):
            dates.check_file(link, self.now)

    def test_cli_expired_redacted_and_exit_one(self):
        self.write({"issued_at_unix": self.now - 100, "expires_at_unix": self.now, "secret": "SENSITIVE_SENTINEL"})
        output = io.StringIO()
        with patch.object(dates.time, "time", return_value=self.now), redirect_stderr(output):
            code = dates.main(["--manifest", str(self.path)])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), "bootstrap-fixture-date-precheck: REJECTED expired\n")

    def test_cli_current_is_not_signature_acceptance(self):
        self.write(self.valid)
        output = io.StringIO()
        with patch.object(dates.time, "time", return_value=self.now), redirect_stdout(output):
            code = dates.main(["--manifest", str(self.path)])
        self.assertEqual(code, 0)
        self.assertIn("signatures and package acceptance still required", output.getvalue())

    def test_no_cli_time_override(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            dates.main(["--manifest", str(self.path), "--now", str(self.now)])
        self.assertEqual(caught.exception.code, 2)

    def test_integer_decoder_failure_is_redacted_at_cli(self):
        self.write(self.valid)
        output = io.StringIO()
        with patch.object(dates.json, "loads", side_effect=ValueError("SENSITIVE_DECODER_SENTINEL")), \
                patch.object(dates.time, "time", return_value=self.now), redirect_stderr(output):
            code = dates.main(["--manifest", str(self.path)])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), "bootstrap-fixture-date-precheck: REJECTED invalid-json\n")


if __name__ == "__main__":
    unittest.main()
