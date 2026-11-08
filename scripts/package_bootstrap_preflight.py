"""Run the actual archived bootstrap binary against public signed bootstrap material."""

import argparse
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

import candidate_metadata as candidate


REJECTED_ERRORS = (ValueError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError)
PHASES = frozenset((
    "resolve-paths", "read-policy", "inspect-archive", "read-public-trust",
    "create-temporary", "extract-archive", "prepare-invocation",
    "execute-bootstrap", "compare-network-id", "cleanup-temporary",
))


def report_rejection(phase, error):
    if isinstance(error, subprocess.TimeoutExpired):
        kind = "subprocess-timeout"
    elif isinstance(error, subprocess.CalledProcessError):
        kind = "subprocess-exit"
    elif isinstance(error, subprocess.SubprocessError):
        kind = "subprocess-error"
    elif isinstance(error, tarfile.TarError):
        kind = "archive-error"
    elif isinstance(error, OSError):
        kind = "os-error"
    elif isinstance(error, KeyError):
        kind = "missing-field"
    else:
        kind = "invalid-value"
    code = getattr(error, "returncode", None)
    code = str(code) if type(code) is int and -255 <= code <= 255 else "unavailable"
    phase = phase if phase in PHASES else "unknown"
    try:
        print(f"bootstrap-preflight-rejected last_phase={phase} kind={kind} returncode={code}", file=sys.stderr)
    except (OSError, ValueError):
        pass  # Preserve the original rejection when diagnostic output fails.


def preflight(archive, policy, version, materials):
    phase = "resolve-paths"
    try:
        archive, materials = Path(archive).resolve(), Path(materials).resolve()
        phase = "read-policy"
        policy_data = candidate.read_json(policy)
        phase = "inspect-archive"
        # Validate every archive member and digest before extraction or execution.
        candidate.inspect_archive(archive, policy_data, version, True)
        phase = "read-public-trust"
        trust = materials / "bootstrap-trust.json"
        network_id = candidate.read_json(trust)["network_id"]
        phase = "create-temporary"
        with tempfile.TemporaryDirectory(prefix="tden-package-bootstrap-") as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            phase = "extract-archive"
            with tarfile.open(archive, "r:gz") as stream:
                stream.extractall(package, filter="data")
            phase = "prepare-invocation"
            argv = [
                str(package / "tden-node-bootstrap"),
                "--manifest", str(materials / "bootstrap-manifest.json"),
                "--trust-config", str(trust),
                "--trust-sha256", candidate.file_sha(trust),
                "--trust-template", str(package / "bootstrap-trust-template.json"),
                "--genesis", str(materials / "genesis.json"),
                "--package-metadata", str(package / "package-metadata.json"),
                "--state", str(root / "state.json"),
                "--format", "network-id",
            ]
            phase = "execute-bootstrap"
            result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60)
            phase = "compare-network-id"
            candidate.require(result.stdout.strip() == network_id, "packaged bootstrap returned a different network ID")
            phase = "cleanup-temporary"
    except REJECTED_ERRORS as error:
        # A cleanup failure can replace a body failure; this is the last entered phase.
        report_rejection(phase, error)
        raise
    print("PASS: archived bootstrap accepted original package metadata/profile and signed public bootstrap material")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--materials", required=True, help="public signed bootstrap-manifest.json, bootstrap-trust.json and genesis.json")
    parser.add_argument("--policy", default="release-policy.json")
    args = parser.parse_args(argv)
    try:
        preflight(args.archive, args.policy, args.version, args.materials)
    except REJECTED_ERRORS:
        parser.exit(1, "packaged bootstrap preflight failed; package or signed public materials were rejected\n")


if __name__ == "__main__":
    main()
