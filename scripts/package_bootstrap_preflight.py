"""Run the actual archived bootstrap binary against public signed bootstrap material."""

import argparse
from pathlib import Path
import subprocess
import tarfile
import tempfile

import candidate_metadata as candidate


def preflight(archive, policy, version, materials):
    archive, materials = Path(archive).resolve(), Path(materials).resolve()
    # This validates every archive member and digest before extraction or execution.
    candidate.inspect_archive(archive, candidate.read_json(policy), version, True)
    trust = materials / "bootstrap-trust.json"
    network_id = candidate.read_json(trust)["network_id"]
    with tempfile.TemporaryDirectory(prefix="tden-package-bootstrap-") as temporary:
        root = Path(temporary)
        package = root / "package"
        package.mkdir()
        with tarfile.open(archive, "r:gz") as stream:
            stream.extractall(package, filter="data")
        result = subprocess.run([
            str(package / "tden-node-bootstrap"),
            "--manifest", str(materials / "bootstrap-manifest.json"),
            "--trust-config", str(trust),
            "--trust-sha256", candidate.file_sha(trust),
            "--trust-template", str(package / "bootstrap-trust-template.json"),
            "--genesis", str(materials / "genesis.json"),
            "--package-metadata", str(package / "package-metadata.json"),
            "--state", str(root / "state.json"),
            "--format", "network-id",
        ], check=True, capture_output=True, text=True, timeout=60)
        candidate.require(result.stdout.strip() == network_id, "packaged bootstrap returned a different network ID")
    print("PASS: archived bootstrap accepted original package metadata/profile and signed public bootstrap material")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--materials", required=True, help="public signed bootstrap-manifest.json, bootstrap-trust.json and genesis.json")
    parser.add_argument("--policy", default="release-policy.json")
    args = parser.parse_args()
    try:
        preflight(args.archive, args.policy, args.version, args.materials)
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError):
        parser.exit(1, "packaged bootstrap preflight failed; package or signed public materials were rejected\n")


if __name__ == "__main__":
    main()
