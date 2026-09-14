"""Validate original package bytes and describe them for a separate GH attestation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


ARCHIVE = "tden-node-linux-amd64.tar.gz"
HELPER = "tden-node-runtime-upgrade"
FILE_TRANSACTION_SCRIPT = "node-runtime-files.py"
PROFILE_NAME = "configuration-profile.json"
PROFILE_FIELDS = {
    "protocol": "tden:node-runtime-configuration-profile:v1",
    "profile_id": "public-node-runtime-rebase-v1",
    "migration": "preserve-state-and-rebase-runtime-v1",
}
PROFILE_ROLE_ARTIFACTS = {
    "chain": "tdend",
    "gateway": "tden-gateway",
    "identity": "tden-identity-node",
    "map": "tden-map-tile-service",
    "node_relay": "tden-node-coordinator",
    "public_supervisor": "tden-public-supervisor",
    "service_approver": "tden-service-approverd",
    "service_repair": "tden-service-repaird",
    "service_worker": "tden-service-workerd",
}
WORKFLOW = ".github/workflows/build-node-candidate.yml"
DESCRIPTION_STEP = "Attest candidate build description"
REPOSITORIES = {
    "chain_commit": "sunbird84/tden-chain",
    "gateway_commit": "sunbird84/tden-gateway",
    "deploy_commit": "sunbird84/tden-deploy",
}
ROOT_FILES = {
    "bootstrap_trust_template_sha256": "bootstrap-trust-template.json",
    "tuf_root_sha256": "tuf-root.json",
}
SMALL_LIMIT = 1024 * 1024
MAX_UNPACKED_BYTES = 2 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(body):
    return json.loads(body, object_pairs_hook=unique_object)


def read_json(path):
    return decode(Path(path).read_bytes())


def sha(body):
    return hashlib.sha256(body).hexdigest()


def file_sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def hex_value(value, size):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % size, value)


def inspect_archive(path, policy, version, runtime_required):
    members, small = {}, {}
    declared_total = actual_total = 0
    with tarfile.open(path, "r|gz") as archive:
        root_seen = False
        for member in archive:
            if member.name in (".", "./") and member.isdir():
                require(not root_seen, "duplicate archive root")
                root_seen = True
                continue
            name = member.name.removeprefix("./")
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name), "unsafe archive member")
            require(name not in members and member.isfile(), f"duplicate or non-regular member: {name}")
            require(not member.issparse(), f"sparse member: {name}")
            require(0 <= member.size <= 2 * 1024**3, f"invalid member size: {name}")
            declared_total += member.size
            require(declared_total <= MAX_UNPACKED_BYTES, "archive declared total exceeds unpacked byte limit")
            require(len(members) < 256, "too many archive members")
            is_small = name.endswith(".json") or name in ("package.sha256", "package-version.txt")
            require(not is_small or member.size <= SMALL_LIMIT, f"oversized metadata: {name}")
            digest, body, prefix, size = hashlib.sha256(), bytearray(), b"", 0
            with archive.extractfile(member) as stream:
                while chunk := stream.read(SMALL_LIMIT):
                    actual_total += len(chunk)
                    require(actual_total <= MAX_UNPACKED_BYTES, "archive actual total exceeds unpacked byte limit")
                    digest.update(chunk)
                    size += len(chunk)
                    if len(prefix) < 20:
                        prefix = (prefix + chunk)[:20]
                    if is_small:
                        body.extend(chunk)
            require(size == member.size, f"truncated member: {name}")
            members[name] = {"sha256": digest.hexdigest(), "bytes": size, "mode": member.mode, "prefix": prefix}
            if is_small:
                small[name] = bytes(body)

    require("package.sha256" in small, "package manifest missing")
    declared = {}
    for line in small["package.sha256"].decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        require(match is not None, "invalid package manifest entry")
        digest, name = match.groups()
        require(name not in declared and name != "package.sha256", "duplicate or self-referential manifest entry")
        declared[name] = digest
    require(set(declared) == set(members) - {"package.sha256"}, "package manifest member set mismatch")
    for name, digest in declared.items():
        require(members[name]["sha256"] == digest, f"package member digest mismatch: {name}")

    metadata = decode(small["package-metadata.json"])
    require(metadata.get("protocol") == "tden:node-runtime-package:v2", "package metadata protocol mismatch")
    require(metadata.get("version") == version and small["package-version.txt"] == (version + "\n").encode(), "package version mismatch")
    require(metadata.get("platform") == "linux-amd64", "package platform mismatch")
    for key, name in ROOT_FILES.items():
        require(hex_value(policy.get(key), 64), f"invalid release policy: {key}")
        require(metadata.get(key) == policy[key] == members[name]["sha256"], f"package trust mismatch: {key}")
    if not runtime_required:
        require(HELPER not in members and "configuration_profile_sha256" not in metadata, "runtime package cannot use legacy provenance")
        return None

    require(HELPER in members, "runtime upgrade helper missing")
    require(FILE_TRANSACTION_SCRIPT in members, "runtime package member node-runtime-files.py missing")
    helper = members[HELPER]
    require(helper["mode"] == 0o755, "runtime upgrade helper must be mode 0755")
    require(helper["prefix"][:6] == b"\x7fELF\x02\x01" and helper["prefix"][18:20] == b"\x3e\x00", "runtime upgrade helper must be ELF64 linux-amd64")
    profile_sha = metadata.get("configuration_profile_sha256")
    require(hex_value(profile_sha, 64), "package metadata must bind configuration_profile_sha256")
    profiles = [name for name in small if name.endswith(".json") and name != "package-metadata.json" and members[name]["sha256"] == profile_sha]
    require(len(profiles) == 1, "configuration profile must identify one manifested JSON file")
    profile_name = profiles[0]
    require(profile_name == PROFILE_NAME, "configuration profile must use fixed member configuration-profile.json")
    profile = decode(small[profile_name])
    require(isinstance(profile, dict), "configuration profile must be an object")
    require(set(profile) == set(PROFILE_FIELDS) | {"role_artifacts"}, "configuration profile must contain exactly four fixed fields")
    for key, value in PROFILE_FIELDS.items():
        require(profile.get(key) == value, f"configuration profile {key} mismatch")
    roles = profile["role_artifacts"]
    require(isinstance(roles, dict) and all(isinstance(value, str) for value in roles.values()), "configuration profile role_artifacts must be a string map")
    require(roles == PROFILE_ROLE_ARTIFACTS, "configuration profile role_artifacts must match fixed nine-role recipe")
    for name in roles.values():
        require(name in members, f"configuration profile role artifact missing: {name}")
    return {
        "release_kind": "node_runtime_bundle",
        "package_manifest_sha256": members["package.sha256"]["sha256"],
        "package_metadata_sha256": members["package-metadata.json"]["sha256"],
        "configuration_profile_sha256": profile_sha,
        "configuration_profile_name": profile_name,
        "helper": {"name": HELPER, "sha256": helper["sha256"], "bytes": helper["bytes"]},
    }


def validate_helper_build(info, gateway_commit):
    require(info.get("Path") == "github.com/tden/tden-gateway/cmd/node-runtime-upgrade", "helper Go command path mismatch")
    require(info.get("GoVersion") == "go1.26.7", "helper Go toolchain mismatch")
    settings = unique_object((item["Key"], item["Value"]) for item in info["Settings"])
    for key, value in {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "vcs": "git", "vcs.revision": gateway_commit, "vcs.modified": "false"}.items():
        require(settings.get(key) == value, f"helper build metadata mismatch: {key}")


def source_repositories(data):
    return {"https://github.com/" + repo: data[key] for key, repo in REPOSITORIES.items()} | {
        "https://github.com/" + data["workflow_repository"]: data["workflow_commit"]
    }


def needs_runtime(jobs):
    steps = [step for page in jobs for job in page["jobs"] for step in job.get("steps", []) if step["name"] == DESCRIPTION_STEP]
    require(len(steps) <= 1, "duplicate description attestation step")
    if steps:
        require(steps[0]["conclusion"] == "success", "description attestation did not succeed")
    return bool(steps)


def validate_receipt(records, name, digest, run, repository):
    invocation = f"https://github.com/{repository}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
    identity_prefix = f"https://github.com/{repository}/{WORKFLOW}@"
    for record in records:
        result = record["verificationResult"]
        cert = result["signature"]["certificate"]
        statement = result["statement"]
        if cert.get("runInvocationURI") != invocation:
            continue
        require(cert.get("issuer") == "https://token.actions.githubusercontent.com", "attestation issuer mismatch")
        require(cert.get("buildSignerURI", "").startswith(identity_prefix), "attestation signer workflow mismatch")
        require(cert.get("sourceRepositoryDigest") == run["head_sha"] == cert.get("buildSignerDigest"), "attestation source commit mismatch")
        require(cert.get("runnerEnvironment") == "github-hosted" and result.get("verifiedTimestamps"), "missing hosted runner or verified timestamp")
        require(statement.get("_type") == "https://in-toto.io/Statement/v1", "attestation statement type mismatch")
        require(statement.get("predicateType") == "https://slsa.dev/provenance/v1", "attestation predicate type mismatch")
        require(statement.get("subject") == [{"name": name, "digest": {"sha256": digest}}], "attestation subject mismatch")
        require(statement["predicate"]["runDetails"]["metadata"]["invocationId"] == invocation, "attestation invocation mismatch")
        return
    raise ValueError("no verified attestation for exact candidate run/attempt")


def validate_description(data, run, repository, digest, size, runtime_required):
    require(data.get("protocol") == "tden:node-candidate-build:v1", "candidate protocol mismatch")
    require(data.get("workflow_repository") == repository and str(data.get("workflow_run_id")) == str(run["id"]), "candidate repository/run mismatch")
    require(data.get("archive_sha256") == digest and data.get("archive_bytes") == size, "candidate archive digest/size mismatch")
    require(isinstance(data.get("version"), str) and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", data["version"]), "candidate version invalid")
    for key in REPOSITORIES:
        require(hex_value(data.get(key), 40), f"invalid source commit: {key}")
    require(("runtime_bundle" in data) == runtime_required, "candidate runtime provenance downgrade/mismatch")
    if runtime_required:
        require(data.get("workflow_commit") == run["head_sha"], "candidate workflow commit mismatch")
        require(str(data.get("workflow_run_attempt")) == str(run["run_attempt"]), "candidate workflow attempt mismatch")
        require(data.get("source_repositories") == source_repositories(data), "candidate source repository binding mismatch")


def create(args):
    root = Path(args.directory)
    data = {
        "protocol": "tden:node-candidate-build:v1",
        "workflow_repository": os.environ["GITHUB_REPOSITORY"],
        "workflow_run_id": os.environ["GITHUB_RUN_ID"],
        "workflow_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "workflow_commit": os.environ["GITHUB_SHA"],
        "version": os.environ["CANDIDATE_VERSION"],
        "archive_sha256": file_sha(root / ARCHIVE),
        "archive_bytes": (root / ARCHIVE).stat().st_size,
    }
    for key, directory in {"chain_commit": "tden-chain", "gateway_commit": "tden-gateway", "deploy_commit": "deploy"}.items():
        path = Path(args.source_root) / directory
        data[key] = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
        require(not subprocess.check_output(["git", "-C", str(path), "status", "--porcelain=v1"], text=True).strip(), f"dirty source: {directory}")
    data["source_repositories"] = source_repositories(data)
    policy = read_json(args.policy)
    data.update({key: policy[key] for key in ROOT_FILES})
    data["runtime_bundle"] = inspect_archive(root / ARCHIVE, policy, data["version"], True)
    runtime = data["runtime_bundle"]
    profile_source = Path(args.source_root) / "deploy/node-installer" / runtime["configuration_profile_name"]
    require(file_sha(profile_source) == runtime["configuration_profile_sha256"], "profile differs from checked-out fixed deployment profile")
    helper_path = Path(args.package_directory) / HELPER
    require(file_sha(helper_path) == runtime["helper"]["sha256"], "helper differs from original archive")
    info = decode(subprocess.check_output(["go", "version", "-m", "-json", str(helper_path)]))
    validate_helper_build(info, data["gateway_commit"])
    validate_description(data, {"id": data["workflow_run_id"], "head_sha": data["workflow_commit"], "run_attempt": data["workflow_run_attempt"]}, data["workflow_repository"], data["archive_sha256"], data["archive_bytes"], True)
    (root / "candidate-build.json").write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps(data, sort_keys=True))


def verify(args):
    root = Path(args.directory)
    data, run = read_json(root / "candidate-build.json"), read_json(args.run)
    runtime_required = needs_runtime(read_json(args.jobs))
    digest, size = file_sha(root / ARCHIVE), (root / ARCHIVE).stat().st_size
    require(digest == os.environ["EXPECTED_SHA256"], "archive differs from approved digest")
    validate_description(data, run, os.environ["GITHUB_REPOSITORY"], digest, size, runtime_required)
    policy = read_json(args.policy)
    for key in ROOT_FILES:
        require(data.get(key) == policy[key], f"candidate trust mismatch: {key}")
    runtime = inspect_archive(root / ARCHIVE, policy, data["version"], runtime_required)
    require(data.get("runtime_bundle") == runtime, "runtime metadata differs from original archive")
    validate_receipt(read_json(args.archive_receipt), ARCHIVE, digest, run, data["workflow_repository"])
    if runtime_required:
        validate_receipt(read_json(args.description_receipt), "candidate-build.json", file_sha(root / "candidate-build.json"), run, data["workflow_repository"])
    print("PASS: original archive, manifest, sources and exact build attestation binding; runtime_bundle=" + str(runtime_required).lower())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("create")
    build.add_argument("--directory", default="output/release")
    build.add_argument("--package-directory", default="output/package")
    build.add_argument("--source-root", default="source")
    build.add_argument("--policy", default="release-policy.json")
    check = sub.add_parser("verify")
    check.add_argument("--directory", default="candidate")
    check.add_argument("--policy", default="release-policy.json")
    check.add_argument("--run", default="run.json")
    check.add_argument("--jobs", default="candidate-jobs.json")
    check.add_argument("--archive-receipt", default="archive-verification.json")
    check.add_argument("--description-receipt", default="description-verification.json")
    args = parser.parse_args()
    try:
        (create if args.command == "create" else verify)(args)
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"candidate verification failed: {error}\n")


if __name__ == "__main__":
    main()
