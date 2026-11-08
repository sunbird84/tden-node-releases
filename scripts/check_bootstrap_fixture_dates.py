"""Cheap date-only rejection before compiling; never a signature acceptance proof."""

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time

# Match the pinned nodebootstrap manifest contract; the archived verifier remains authoritative.
MAX_BYTES = 256 * 1024
MAX_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 10 * 60


class FixtureDateError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureDateError("duplicate-fields")
        result[key] = value
    return result


def check_dates(manifest, now):
    if type(now) is not int or now <= 0:
        raise FixtureDateError("clock-unavailable")
    if type(manifest) is not dict:
        raise FixtureDateError("invalid-shape")
    issued, expires = manifest.get("issued_at_unix"), manifest.get("expires_at_unix")
    if any(type(value) is not int or not -(2**63) <= value < 2**63 for value in (issued, expires)):
        raise FixtureDateError("invalid-date-fields")
    if issued > now + MAX_CLOCK_SKEW_SECONDS:
        raise FixtureDateError("future-issued")
    if expires <= now:
        raise FixtureDateError("expired")
    if expires <= issued:
        raise FixtureDateError("inverted-window")
    if expires - issued > MAX_AGE_SECONDS:
        raise FixtureDateError("excess-lifetime")


def check_file(path, now):
    path = Path(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise FixtureDateError("non-regular-file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise FixtureDateError("non-regular-file")
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise FixtureDateError("file-changed")
            if not 0 < opened.st_size <= MAX_BYTES:
                raise FixtureDateError("invalid-size")
            body = stream.read(MAX_BYTES + 1)
        if not 0 < len(body) <= MAX_BYTES:
            raise FixtureDateError("invalid-size")
    except OSError:
        raise FixtureDateError("read-failed") from None
    try:
        manifest = json.loads(body, object_pairs_hook=unique_object)
    except FixtureDateError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise FixtureDateError("invalid-json") from None
    check_dates(manifest, now)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    try:
        check_file(args.manifest, int(time.time()))
    except FixtureDateError as error:
        print("bootstrap-fixture-date-precheck: REJECTED " + str(error), file=sys.stderr)
        return 1
    print("bootstrap-fixture-date-precheck: dates current; signatures and package acceptance still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
