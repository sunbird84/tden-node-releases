"""Check a downloaded candidate against operator-recorded final source refs.

Receipts must first be produced by the publisher's gh attestation verify commands.
This local check does not cryptographically verify receipts or authorize stable.
"""

import argparse
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

import candidate_metadata as candidate


def check_lock(data, run, args):
    for key in (*candidate.REPOSITORIES, "workflow_commit"):
        expected = getattr(args, key)
        candidate.require(candidate.hex_value(expected, 40), f"invalid expected source: {key}")
        candidate.require(data.get(key) == expected, f"final source lock mismatch: {key}")
    candidate.require(data.get("version") == args.version, "final version lock mismatch")
    candidate.require(candidate.hex_value(args.archive_sha256, 64), "invalid expected archive digest")
    candidate.require(data.get("archive_sha256") == args.archive_sha256, "final archive lock mismatch")
    for key, expected in (("id", args.run_id), ("run_attempt", args.run_attempt)):
        candidate.require(type(expected) is int and expected > 0 and run.get(key) == expected,
                          f"final build lock mismatch: {key}")
    candidate.require("runtime_bundle" in data, "final source lock requires runtime provenance")


def scan_isolation(archive, deploy_source, deploy_commit):
    source = Path(deploy_source).resolve()
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    candidate.require(head == deploy_commit, "isolation scanner Deploy commit mismatch")
    status = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain=v1"], text=True).strip()
    candidate.require(not status, "isolation scanner requires clean Deploy source")
    scanner = source / "node-installer/assert-release-isolation.ps1"
    candidate.require(scanner.is_file() and not scanner.is_symlink(), "release isolation scanner missing or linked")
    # Caller has already verified every flat regular member with inspect_archive.
    with tempfile.TemporaryDirectory(prefix="tden-source-lock-") as temporary:
        package = Path(temporary)
        with tarfile.open(archive, "r:gz") as stream:
            stream.extractall(package, filter="data")
        # Same vendor exception as the official packager: separately pinned Kubo.
        env = dict(os.environ, TDEN_SOURCE_LOCK_SCANNER=str(scanner), TDEN_SOURCE_LOCK_PACKAGE=str(package))
        subprocess.run([
            "pwsh", "-NoProfile", "-Command",
            "$ErrorActionPreference = 'Stop'; & $env:TDEN_SOURCE_LOCK_SCANNER -Paths "
            "@(Get-ChildItem -LiteralPath $env:TDEN_SOURCE_LOCK_PACKAGE -File | "
            "Where-Object Name -ne 'kubo.tar.gz' | Select-Object -ExpandProperty FullName)",
        ], env=env, check=True)


def check(args):
    root = Path(args.directory)
    data = candidate.read_json(root / "candidate-build.json")
    run = candidate.read_json(args.run)
    check_lock(data, run, args)
    candidate.verify(args, repository=args.repository, expected_sha256=args.archive_sha256)
    scan_isolation(root / candidate.ARCHIVE, args.deploy_source, args.deploy_commit)
    print("PASS: local final-source lock and existing release isolation scan; NOT installation acceptance or stable authorization")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--repository", default="sunbird84/tden-node-releases")
    parser.add_argument("--policy", default="release-policy.json")
    parser.add_argument("--run", required=True)
    parser.add_argument("--jobs", required=True)
    parser.add_argument("--archive-receipt", required=True)
    parser.add_argument("--description-receipt", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    for key in (*candidate.REPOSITORIES, "workflow_commit"):
        parser.add_argument("--" + key.replace("_", "-"), required=True)
    parser.add_argument("--deploy-source", required=True, help="clean Deploy checkout at the locked commit")
    args = parser.parse_args()
    try:
        check(args)
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"source lock verification failed: {error}\n")


if __name__ == "__main__":
    main()
