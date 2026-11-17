#!/usr/bin/env python3
"""Fixed-host upload through an existing local curl. Credentials stay in pipes."""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

NAMES = {"candidate-build.json", "tden-node-linux-amd64.tar.gz", "tden-node-linux-amd64.tar.gz.sha256"}
PROTOCOL = "tden:local-preview-curl-upload:v1"
MARKER = b"\nTDEN_UPLOAD_STATUS="


class UploadError(Exception):
    def __init__(self, code, **diagnostics):
        self.code, self.diagnostics = code, diagnostics


def require(ok, code):
    if not ok:
        raise UploadError(code)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    result = hashlib.sha256()
    while True:
        data = os.read(fd, 1024 * 1024)
        if not data:
            break
        result.update(data)
    os.lseek(fd, 0, os.SEEK_SET)
    return result.hexdigest()


def upload(release_id, filename, name, expected_bytes, expected_sha256, token, runner=subprocess.run):
    require(type(release_id) is int and 0 < release_id < 2**53, "RELEASE_ID")
    require(name in NAMES and os.path.basename(filename) == name, "ASSET_NAME")
    require(os.path.isabs(filename), "ASSET_PATH")
    require(type(expected_bytes) is int and 0 < expected_bytes <= 1024**3, "ASSET_BYTES")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None, "ASSET_DIGEST")
    require(isinstance(token, bytes) and re.fullmatch(rb"[A-Za-z0-9_]{20,4096}", token) is not None, "AUTH_FORMAT")
    before = os.lstat(filename)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == expected_bytes, "ASSET_FILE")
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(identity(before) == identity(os.fstat(fd)), "ASSET_CHANGED")
        require(digest(fd) == expected_sha256, "ASSET_DIGEST_MISMATCH")
        require(identity(before) == identity(os.fstat(fd)) == identity(os.lstat(filename)), "ASSET_CHANGED")
        url = f"https://uploads.github.com/repos/sunbird84/tden-node-releases/releases/{release_id}/assets?name={name}"
        args = ["/usr/bin/curl", "-q", "--silent", "--show-error", "--http2",
                "--proto", "=https", "--connect-timeout", "15", "--max-time", "840",
                "--retry", "0", "--request", "POST", "--url", url,
                "--header", "Accept: application/vnd.github+json",
                "--header", "Content-Type: application/octet-stream",
                "--header", "X-GitHub-Api-Version: 2022-11-28",
                "--data-binary", f"@/proc/self/fd/{fd}", "--config", "-",
                "--write-out", "\nTDEN_UPLOAD_STATUS=%{http_code} %{size_upload} %{time_total} %{ssl_verify_result} %{http_version}\n"]
        # Never put the bearer token in argv, environment, a config file or logs.
        config = b'header = "Authorization: Bearer ' + token + b'"\n'
        try:
            result = runner(args, input=config, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=850, check=False, pass_fds=(fd,),
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
        except subprocess.TimeoutExpired:
            raise UploadError("PROCESS_TIMEOUT") from None
        finally:
            config = b""
        require(identity(before) == identity(os.fstat(fd)) == identity(os.lstat(filename)), "ASSET_CHANGED")
        require(digest(fd) == expected_sha256, "ASSET_CHANGED")
        require(identity(before) == identity(os.fstat(fd)) == identity(os.lstat(filename)), "ASSET_CHANGED")
        # Response and stderr remain memory-only. Expose closed diagnostics, never raw text.
        parts = result.stdout.rsplit(MARKER, 1)
        info = {"curl_exit": result.returncode if 0 <= result.returncode <= 255 else -1,
                "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
        if len(parts) == 2:
            match = re.fullmatch(rb"([0-9]{3}) ([0-9]{1,12}) ([0-9]{1,6}\.[0-9]{1,6}) ([0-9]{1,10}) (0|1(?:\.0|\.1)?|2|3)\n", parts[1])
            if match:
                info.update(http_status=int(match[1]), uploaded_bytes=int(match[2]),
                            total_seconds=float(match[3]), tls_verify=int(match[4]), http_version=match[5].decode("ascii"))
        if (result.returncode != 0 or info.get("http_status") != 201 or info.get("tls_verify") != 0
                or info.get("http_version") not in ("1.1", "2")):
            raise UploadError("TRANSFER_FAILED", **info)
        require(info.get("uploaded_bytes") == expected_bytes, "TRANSFER_SIZE")
        try:
            asset = json.loads(parts[0])
        except (ValueError, UnicodeError):
            raise UploadError("RESPONSE_JSON") from None
        require(isinstance(asset, dict) and type(asset.get("id")) is int and 0 < asset["id"] < 2**53
                and asset.get("name") == name and asset.get("state") == "uploaded"
                and type(asset.get("size")) is int and asset["size"] == expected_bytes
                and asset.get("digest") == "sha256:" + expected_sha256, "RESPONSE_BINDING")
        return {"protocol": PROTOCOL, "ok": True, "asset_id": asset["id"], "name": name,
                "bytes": expected_bytes, "sha256": expected_sha256, **info}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-id", type=int, required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--name", choices=sorted(NAMES), required=True)
    parser.add_argument("--bytes", type=int, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    token = sys.stdin.buffer.read(4098)
    try:
        result = upload(args.release_id, args.file, args.name, args.bytes, args.sha256, token.rstrip(b"\r\n"))
    except UploadError as error:
        result = {"protocol": PROTOCOL, "ok": False, "code": error.code, **error.diagnostics}
    except Exception:
        result = {"protocol": PROTOCOL, "ok": False, "code": "LOCAL_IO_ERROR"}
    token = b""
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
