"""Fetch one pinned public Kubo asset for a fresh GitHub-hosted build."""

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.github.com/repos/ipfs/kubo/releases/assets/441662929"
DOWNLOAD_PATH = "/ipfs/kubo/releases/download/v0.42.0/kubo_v0.42.0_linux-amd64.tar.gz"
ARCHIVE_NAME = "kubo_v0.42.0_linux-amd64.tar.gz"
EXPECTED_SIZE = 54571642
EXPECTED_SHA256 = "284145534168b51fe980f73c90f0ce84b55ca293034836b2ba8ea8f93435116e"
EXPECTED_SHA512 = "054c38a0cf66f7d738e25085ad62cb3a42d03d4bac329b7dd25c1d71cf18e1ce87d55b1d1b705b04c65210dca9109973579e0eb1cd72f6341ecb3311d840d156"
MAX_SECONDS = 180
MAX_REDIRECTS = 3
REDIRECTS = {301, 302, 303, 307, 308}


class AcquisitionError(Exception):
    pass


def reject(code):
    raise AcquisitionError(code)


def validate_url(url):
    try:
        u = urllib.parse.urlsplit(url)
        if (u.scheme != "https" or u.username is not None or u.password is not None
                or u.port not in (None, 443) or u.fragment):
            reject("redirect-policy")
        if u.hostname == "api.github.com" and url == API_URL:
            return
        if u.hostname == "github.com" and u.path == DOWNLOAD_PATH and not u.query:
            return
        if u.hostname == "release-assets.githubusercontent.com" and re.fullmatch(
                r"/github-production-release-asset/21233191/[A-Za-z0-9-]+", u.path):
            return
    except ValueError:
        pass
    reject("redirect-policy")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_remote(url, headers, timeout):
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(NoRedirect())
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as response:
        return response


def fresh_directory(root, run_id, attempt):
    root = Path(root)
    if not root.is_absolute() or any(c in str(root) for c in "\r\n"):
        reject("temporary-root")
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", attempt):
        reject("run-identity")
    for item in (root, *root.parents):
        if not stat.S_ISDIR(item.lstat().st_mode) or item.is_symlink():
            reject("temporary-root")
    if root.resolve() != root:
        reject("temporary-root")
    directory = root / ("tden-kubo-" + run_id + "-" + attempt)
    directory.mkdir(mode=0o700, exist_ok=False)
    return directory


def acquire(root, run_id, attempt, token, transport=open_remote, clock=time.monotonic):
    if not token or any(c.isspace() for c in token):
        reject("token-unavailable")
    directory = fresh_directory(root, run_id, attempt)
    target = directory / ARCHIVE_NAME
    deadline = clock() + MAX_SECONDS
    url = API_URL
    for hop in range(MAX_REDIRECTS + 1):
        validate_url(url)
        remaining = deadline - clock()
        if remaining <= 0:
            reject("deadline")
        headers = {"Accept": "application/octet-stream", "User-Agent": "TDEN-pinned-Kubo-build"}
        if url == API_URL:
            headers["Authorization"] = "Bearer " + token
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        with transport(url, headers, min(30, remaining)) as response:
            if response.status in REDIRECTS:
                if hop == MAX_REDIRECTS:
                    reject("redirect-limit")
                location = response.headers.get("Location")
                if not location:
                    reject("redirect-missing")
                url = urllib.parse.urljoin(url, location)
                validate_url(url)
                continue
            if response.status != 200:
                reject("http-status")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            if content_type in {"application/json", "text/html"}:
                reject("non-archive-response")
            length = response.headers.get("Content-Length")
            if length is not None and (not re.fullmatch(r"[0-9]+", length) or int(length) != EXPECTED_SIZE):
                reject("declared-size")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, 0o600)
            count, sha256, sha512 = 0, hashlib.sha256(), hashlib.sha512()
            with os.fdopen(fd, "wb") as output:
                while True:
                    if clock() >= deadline:
                        reject("deadline")
                    chunk = response.read(min(65536, EXPECTED_SIZE - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > EXPECTED_SIZE:
                        reject("received-size")
                    output.write(chunk)
                    sha256.update(chunk)
                    sha512.update(chunk)
                if count != EXPECTED_SIZE:
                    reject("received-size")
                if sha256.hexdigest() != EXPECTED_SHA256 or sha512.hexdigest() != EXPECTED_SHA512:
                    reject("digest")
                output.flush()
                os.fsync(output.fileno())
            return {"archive": str(target), "bytes": count, "sha256": sha256.hexdigest(),
                    "sha512": sha512.hexdigest(), "source": "ipfs/kubo:asset441662929"}
    reject("redirect-limit")


def publish_output(receipt, output_file):
    path = Path(output_file)
    if not path.is_absolute() or not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink():
        reject("output-file")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as output:
        output.write("archive=" + receipt["archive"] + "\n")


def main():
    try:
        if sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true":
            reject("runner-required")
        signal.signal(signal.SIGALRM, lambda *_: reject("deadline"))
        signal.setitimer(signal.ITIMER_REAL, MAX_SECONDS)
        try:
            receipt = acquire(os.environ["RUNNER_TEMP"], os.environ["GITHUB_RUN_ID"],
                              os.environ["GITHUB_RUN_ATTEMPT"], os.environ.get("GITHUB_TOKEN", ""))
            publish_output(receipt, os.environ["GITHUB_OUTPUT"])
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except AcquisitionError as exc:
        print("Pinned Kubo acquisition failed: " + str(exc), file=sys.stderr)
    except Exception:
        # urllib errors can contain signed redirect URLs; never log them.
        print("Pinned Kubo acquisition failed: transport-or-local-io", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
