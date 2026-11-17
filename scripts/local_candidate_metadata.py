"""Create and reverify an explicitly local, preview-only node candidate.

The public candidate-build:v1 package fields remain compatible with Native.
This is a local observation, not a hosted attestation or release authorization.
"""

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile

# -I intentionally removes the script directory. Import only this fixed sibling.
SCRIPT_ROOT = Path(__file__).resolve().parent
CONTROL_ROOT = SCRIPT_ROOT.parent
sys.path.insert(0, str(SCRIPT_ROOT))
import candidate_metadata as hosted


REQUEST_PROTOCOL = "tden:node-local-preview-request:v1"
PROVENANCE_PROTOCOL = "tden:node-local-build-provenance:v1"
VERIFICATION_PROTOCOL = "tden:node-local-preview-verification:v1"
ARCHIVE = "tden-node-linux-amd64.tar.gz"
ASSETS = {ARCHIVE, ARCHIVE + ".sha256", "candidate-build.json"}
REPOSITORIES = {
    "tden-chain": "https://github.com/sunbird84/tden-chain",
    "tden-gateway": "https://github.com/sunbird84/tden-gateway",
    "deploy": "https://github.com/sunbird84/tden-deploy",
}
MEMBERS = set("""approval-attestations.txt bootstrap-trust-template.json
build-clean-network-base.sh configuration-profile.json finalize-clean-network.sh
install.sh kubo.tar.gz lifecycle-gateway-trust.json node-runtime-files.py
package-metadata.json package-version.txt package.sha256 prepare-clean-validator.sh
public-endpoint.sh release-trust-template.json resolve-public-ca-route.py
sign-clean-validator-gentx.sh tden-gateway tden-identity-node tden-map-tile-service
tden-node-agent tden-node-bootstrap tden-node-bootstrap-material tden-node-configure
tden-node-control-mode tden-node-coordinator tden-node-keygen tden-node-lifecycle-helper
tden-node-lifecycled tden-node-public-handoff tden-node-release-configure
tden-node-runtime-upgrade tden-node-service-config tden-public-lockdown
tden-public-recovery tden-public-reward-release tden-public-supervisor
tden-security-agent tden-service-approverd tden-service-offerd tden-service-repaird
tden-service-workerd tdend tuf-root.json upgrade-managed-node-package.sh""".split())
CHANGED = {"node-runtime-files.py", "package-metadata.json", "package-version.txt", "package.sha256"}
MAX_ARCHIVE = 1024 ** 3
MAX_DECODED = 2 * 1024 ** 3
ERROR_STAGE = "REQUEST"
PINNED_BUILD_TOOLS = {
    "go": ("/root/TDEN2_LOCAL_NODE_20261112/tools/go-archive/go/bin/go", "182d1dc98119d61a6241590e1aaca180d771dbcb1133b9846684aee82d457362"),
    "powershell": ("/root/TDEN2_LOCAL_NODE_20261112/tools/powershell/pwsh", "e0c6c82153c6655a842602be4ea7607d4e3a137b1956668ef44d1b1b7bf939b8"),
}
SYSTEM_GIT = Path("/usr/bin/git")


def stage(value):
    global ERROR_STAGE
    ERROR_STAGE = value


def need(condition, message):
    if not condition:
        raise ValueError(message)


def closed(value, keys, label):
    need(type(value) is dict and set(value) == set(keys), label + " fields differ")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def is_hex(value, size=64):
    return type(value) is str and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def decode(body):
    return json.loads(body, object_pairs_hook=hosted.unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def regular(path, maximum=None):
    path = Path(path)
    need(path.is_absolute(), "absolute local path required")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode), "regular unlinked input required")
    need(maximum is None or 0 < info.st_size <= maximum, "input size exceeds bound")
    return info


def file_sha(path, maximum=None):
    before = regular(path, maximum)
    with Path(path).open("rb") as stream:
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "input replaced before read")
        result = hashlib.file_digest(stream, "sha256").hexdigest()
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "input changed during read")
    need(stamp(Path(path).lstat()) == stamp(before), "input replaced during read")
    return result


def bounded_bytes(path, maximum=2 * 1024 ** 2):
    before = regular(path, maximum)
    with Path(path).open("rb") as stream:
        body = stream.read(maximum + 1)
        need(len(body) == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before),
             "bounded input changed")
    need(stamp(Path(path).lstat()) == stamp(before), "bounded input replaced")
    return body


def checked_input(value, label, *, tool=False):
    closed(value, {"path", "sha256"}, label)
    need(is_hex(value["sha256"]), label + " digest invalid")
    path = Path(value["path"])
    need(path.is_absolute(), label + " path must be absolute")
    # System interpreters may be trusted symlinks; regular data inputs may not.
    if tool:
        path = path.resolve(strict=True)
    need(file_sha(path) == value["sha256"], label + " digest mismatch")
    return path


def bound_json(value, label):
    path = checked_input(value, label)
    body = bounded_bytes(path)
    need(digest(body) == value["sha256"], label + " changed before decoding")
    return path, decode(body)


def command(args, *, env=None):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=45, env=env)
    need(result.returncode == 0 and len(result.stdout) <= 4 * 1024 ** 2,
         "local verification command failed")
    return result.stdout


def verification_env():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GIT_", "GO")) and key not in ("GH_TOKEN", "GITHUB_TOKEN", "GH_DEBUG")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GOENV="off", GOTOOLCHAIN="local",
               GOPROXY="off", GOSUMDB="off", PYTHONDONTWRITEBYTECODE="1")
    return env


def git(git_tool, path, *args):
    return command([git_tool, "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", path, *args],
                   env=verification_env()).decode("utf-8").strip()


def repository(value, git_tool):
    closed(value, {"path", "commit"}, "source")
    need(is_hex(value["commit"], 40), "source commit invalid")
    path = Path(value["path"])
    need(path.is_absolute() and path.is_dir(), "source directory unavailable")
    need(git(git_tool, path, "rev-parse", "HEAD") == value["commit"], "source commit mismatch")
    need(not git(git_tool, path, "status", "--porcelain=v1", "--untracked-files=all"), "dirty source tree")
    tree = git(git_tool, path, "rev-parse", "HEAD^{tree}")
    need(is_hex(tree, 40), "source tree invalid")
    return path.resolve(), tree


def timestamp(value):
    need(type(value) is str, "build timestamp must be a string")
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(result.tzinfo is not None, "build timestamp lacks timezone")
    return result


def file_records(rows):
    need(type(rows) is list and len(rows) == 45, "build receipt member count differs")
    result = {}
    for row in rows:
        need(type(row) is dict and row.get("name") in MEMBERS and row["name"] not in result,
             "build receipt member names differ")
        need(type(row.get("bytes")) is int and row["bytes"] >= 0 and is_hex(row.get("sha256")),
             "build receipt member digest/size invalid")
        result[row["name"]] = {"bytes": row["bytes"], "sha256": row["sha256"]}
    need(set(result) == MEMBERS, "build receipt member closure differs")
    return result


def archive_members(path):
    """Read raw tar blocks through gzip EOF, including CRC and bounded zero tail.

    Do not let tarfile silently consume PAX/GNU extension bodies or stop before
    compressed EOF. No member is extracted or executed by this pass.
    """
    before = regular(path, MAX_ARCHIVE)
    members, small, total, root_seen = {}, {}, 0, False
    with gzip.open(path, "rb") as stream:
        while True:
            header = stream.read(512)
            need(len(header) == 512, "tar EOF marker missing")
            total += 512
            need(total <= MAX_DECODED, "decoded archive exceeds bound")
            if header == bytes(512):
                tail = stream.read(65537)
                need(512 <= len(tail) <= 65536 and not any(tail), "invalid or excessive tar tail")
                total += len(tail)
                need(total <= MAX_DECODED, "decoded tail exceeds bound")
                need(not stream.read(1), "gzip tail exceeds bound")
                break
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if member.name in (".", "./") and member.type == tarfile.DIRTYPE:
                need(not root_seen and member.size == 0, "invalid archive root")
                root_seen = True
                continue
            name = member.name.removeprefix("./")
            need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and name in MEMBERS
                 and name not in members and not member.linkname, "unsafe or duplicate archive member")
            need(member.mode in (0o644, 0o755) and 0 <= member.size <= MAX_ARCHIVE,
                 "archive member mode/size invalid")
            need(len(members) < 45 and total + member.size <= MAX_DECODED, "archive member bound exceeded")
            is_small = name.endswith(".json") or name in ("package.sha256", "package-version.txt")
            need(not is_small or member.size <= hosted.SMALL_LIMIT, "metadata exceeds bound")
            hashed, body, left = hashlib.sha256(), bytearray(), member.size
            while left:
                chunk = stream.read(min(left, 65536))
                need(chunk, "truncated tar member")
                hashed.update(chunk)
                if is_small:
                    body.extend(chunk)
                left -= len(chunk)
            padding = (-member.size) % 512
            need(stream.read(padding) == bytes(padding), "invalid tar member padding")
            total += member.size + padding
            need(total <= MAX_DECODED, "decoded padding exceeds bound")
            members[name] = {"bytes": member.size, "sha256": hashed.hexdigest()}
            if is_small:
                small[name] = bytes(body)
    need(set(members) == MEMBERS, "archive must contain exactly original 45 members")
    need(stamp(Path(path).lstat()) == stamp(before), "archive changed during verification")
    return members, small


def go_vcs(go_tool, artifact, commit, expected_command):
    info = decode(command([go_tool, "version", "-m", "-json", artifact], env=verification_env()))
    need(info.get("Path") == expected_command and info.get("GoVersion") == "go1.26.7",
         "Go binary command/toolchain differs")
    settings = hosted.unique_object((row["Key"], row["Value"]) for row in info["Settings"])
    for key, value in {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "vcs": "git",
                       "vcs.revision": commit, "vcs.modified": "false"}.items():
        need(settings.get(key) == value, "Go VCS or build settings differ")


def load_request(path):
    value = decode(bounded_bytes(path))
    closed(value, {"protocol", "version", "archive", "build_receipt", "baseline_receipt", "control",
                   "sources", "tools", "scripts", "policy"}, "request")
    need(value["protocol"] == REQUEST_PROTOCOL, "local request protocol mismatch")
    need(type(value["version"]) is str and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", value["version"])
         and "-test." in value["version"], "local publication requires a TEST version")
    closed(value["archive"], {"path", "bytes", "sha256"}, "archive")
    need(type(value["archive"]["bytes"]) is int and 0 < value["archive"]["bytes"] <= MAX_ARCHIVE
         and is_hex(value["archive"]["sha256"]), "archive binding invalid")
    closed(value["sources"], REPOSITORIES, "sources")
    closed(value["tools"], {"go", "powershell", "python", "git"}, "tools")
    closed(value["scripts"], {"build_driver", "bootstrap_preflight"}, "scripts")
    return value


def candidate(request, *, archive_override=None):
    stage("TOOLS")
    tools = {name: checked_input(value, "tool " + name, tool=True) for name, value in request["tools"].items()}
    need(tools["python"] == Path(sys.executable).resolve(), "verification interpreter differs")
    need(tools["git"] == SYSTEM_GIT.resolve(strict=True), "verification git differs from system binary")
    for name, (path, sha) in PINNED_BUILD_TOOLS.items():
        need(tools[name] == Path(path).resolve(strict=True) and request["tools"][name]["sha256"] == sha,
             "build tool differs from fixed recipe")
    scripts = {name: checked_input(value, "recipe " + name) for name, value in request["scripts"].items()}
    driver = bounded_bytes(scripts["build_driver"])
    need(digest(driver) == request["scripts"]["build_driver"]["sha256"], "build driver changed")
    for name, (_, sha) in PINNED_BUILD_TOOLS.items():
        variable = "go" if name == "go" else "pwsh"
        need(("need(sha(" + variable + ")==\'" + sha + "\'").encode() in driver,
             "build recipe lacks recorded tool pin")
    stage("SOURCE")
    control, _ = repository(request["control"], tools["git"])
    # A clean Linux checkout can bind an executing copy on a Windows mount.
    # Python already treats CRLF/LF alike; preserve both source and execution hashes.
    for name in ("local_candidate_metadata.py", "candidate_metadata.py"):
        need(bounded_bytes(SCRIPT_ROOT / name).replace(b"\r\n", b"\n") ==
             bounded_bytes(control / "scripts" / name).replace(b"\r\n", b"\n"),
             "executing verifier differs from pinned clean source")
    source_state = {name: repository(value, tools["git"]) for name, value in request["sources"].items()}
    stage("RECEIPT")
    receipt_path, receipt = bound_json(request["build_receipt"], "build receipt")
    baseline_path, baseline = bound_json(request["baseline_receipt"], "baseline receipt")
    policy_path, policy = bound_json(request["policy"], "release policy")
    need(policy_path.resolve() == (control / "release-policy.json").resolve(), "policy is outside pinned control")
    need(receipt.get("protocol") == "tden:terminal-sync-recovery-local-node-build:v1"
         and receipt.get("version") == request["version"], "build receipt protocol/version differs")
    need(all(receipt.get(key) is True for key in ("buildAccepted", "allSourceCheckoutsClean", "originalVerifierAccepted",
                                                "networkNamespaceIsolated")), "build not accepted")
    need(all(receipt.get(key) is False for key in ("officialProvenance", "published", "deployed", "cloudMutation")),
         "local build receipt claims unrelated authority")
    commits = {name: value["commit"] for name, value in request["sources"].items()}
    need(receipt.get("sourceCommits") == commits and set(receipt.get("sources", {})) == set(commits),
         "build source binding differs")
    for name, (path, tree) in source_state.items():
        recorded = receipt["sources"][name]
        need(recorded.get("commit") == commits[name] and recorded.get("tree") == tree
             and Path(recorded.get("path", "")).resolve() == path, "receipt source tree/path differs")
    need(receipt.get("baseline", {}).get("sha256") == request["baseline_receipt"]["sha256"]
         and Path(receipt["baseline"]["path"]).resolve() == baseline_path.resolve()
         and baseline.get("buildAccepted") is True, "baseline not bound")
    need(receipt.get("archive") == request["archive"], "receipt archive binding differs")
    start, finish = timestamp(receipt["startedAtUTC"]), timestamp(receipt["finishedAtUTC"])
    need(start <= finish, "build time order invalid")
    steps = receipt.get("steps")
    expected_steps = ["whole-package", "vcs-tdend", "vcs-tden-gateway", "capability", "archive", "bootstrap-preflight"]
    need(type(steps) is list and [row.get("name") for row in steps] == expected_steps, "build steps differ")
    previous = start
    for step in steps:
        need(type(step.get("exitCode")) is int and step["exitCode"] == 0
             and is_hex(step.get("logSHA256")), "build step unsuccessful")
        began, ended = timestamp(step["startedAtUTC"]), timestamp(step["finishedAtUTC"])
        need(previous <= began <= ended <= finish, "build step time order invalid")
        need(file_sha(step["log"], 16 * 1024 ** 2) == step["logSHA256"], "build log digest differs")
        previous = ended
    stage("ARCHIVE")
    archive = Path(archive_override or request["archive"]["path"])
    before = regular(archive, MAX_ARCHIVE)
    need(before.st_size == request["archive"]["bytes"] and file_sha(archive) == request["archive"]["sha256"],
         "archive digest/size differs")
    members, small = archive_members(archive)
    need(members == file_records(receipt["files"]), "archive differs from actual build members")
    old = file_records(baseline["files"])
    need({name for name in MEMBERS if members[name] != old[name]} == CHANGED
         and set(receipt.get("changedPackageMembers", [])) == CHANGED, "unexpected package changes")
    old_metadata = bounded_bytes(baseline_path.parent / "package-metadata.json")
    need(digest(old_metadata) == old["package-metadata.json"]["sha256"], "baseline metadata digest differs")
    expected_metadata = decode(old_metadata)
    expected_metadata["version"] = request["version"]
    need(decode(small["package-metadata.json"]) == expected_metadata, "metadata changed beyond version")
    need(receipt.get("internalManifestSHA256") == members["package.sha256"]["sha256"], "manifest binding differs")
    runtime = hosted.inspect_archive(archive, policy, request["version"], True)
    stage("PACKAGE")
    package = Path(request["archive"]["path"]).parent / "package"
    need(package.is_dir() and {p.name for p in package.iterdir()} == MEMBERS, "local package closure differs")
    for name in MEMBERS:
        need(regular(package / name).st_size == members[name]["bytes"]
             and file_sha(package / name) == members[name]["sha256"], "local package member differs")
    deploy = source_state["deploy"][0] / "node-installer"
    need(file_sha(deploy / "node-runtime-files.py") == members["node-runtime-files.py"]["sha256"],
         "packaged helper differs from clean source")
    need(file_sha(deploy / hosted.PROFILE_NAME) == runtime["configuration_profile_sha256"],
         "configuration profile differs from clean source")
    for name, source, module in (("tdend", "tden-chain", "github.com/tden/tden-chain/cmd/tdend"),
                                 ("tden-gateway", "tden-gateway", "github.com/tden/tden-gateway/cmd/gateway"),
                                 ("tden-node-runtime-upgrade", "tden-gateway", "github.com/tden/tden-gateway/cmd/node-runtime-upgrade")):
        stage("GO_VCS")
        go_vcs(tools["go"], package / name, commits[source], module)
        need(file_sha(package / name) == members[name]["sha256"], "binary changed during metadata check")
    stage("SOURCE")
    for value in [request["control"], *request["sources"].values()]:
        repository(value, tools["git"])
    need(file_sha(archive) == request["archive"]["sha256"] and stamp(archive.lstat()) == stamp(before),
         "archive changed during verification")
    recipe_hashes = {name: request["scripts"][name]["sha256"] for name in scripts}
    recipe_hashes.update(package_builder=file_sha(deploy / "build-node-package.ps1"),
                         archive_packager=file_sha(deploy / "archive-node-package.py"))
    provenance = {
        "protocol": PROVENANCE_PROTOCOL, "evidence_kind": "local_build_record_reverified",
        "build_started_at": steps[0]["startedAtUTC"], "build_finished_at": steps[0]["finishedAtUTC"],
        "record_started_at": receipt["startedAtUTC"], "record_finished_at": receipt["finishedAtUTC"],
        "build_receipt_sha256": request["build_receipt"]["sha256"],
        "baseline_receipt_sha256": request["baseline_receipt"]["sha256"],
        "source_repositories": {REPOSITORIES[name]: commits[name] for name in REPOSITORIES},
        "source_trees": {REPOSITORIES[name]: source_state[name][1] for name in REPOSITORIES},
        "control_commit": request["control"]["commit"],
        "build_tools": {name: request["tools"][name]["sha256"] for name in ("go", "powershell")},
        "build_tools_observation": "build_driver_pinned_reverified",
        "verification_tools": {name: request["tools"][name]["sha256"] for name in ("python", "git")},
        "recipe_sha256": recipe_hashes, "recipe_observation": "post_build_reverification",
        "verification_code_sha256": {name: file_sha(control / "scripts" / name)
                                     for name in ("local_candidate_metadata.py", "candidate_metadata.py")},
        "executed_verification_code_sha256": {name: file_sha(SCRIPT_ROOT / name)
                                              for name in ("local_candidate_metadata.py", "candidate_metadata.py")},
    }
    return {"protocol": "tden:node-candidate-build:v1", "version": request["version"],
            "archive_sha256": request["archive"]["sha256"], "archive_bytes": request["archive"]["bytes"],
            **{key: policy[key] for key in hosted.ROOT_FILES}, "runtime_bundle": runtime,
            "build_environment": "local", "local_build_provenance": provenance}


def tag_for(request):
    slug = re.sub(r"[^a-z0-9]+", "-", request["version"].lower()).strip("-")
    return "node-" + slug + "-local-" + request["archive"]["sha256"]


def verify(request, directory):
    stage("DESCRIPTOR")
    directory = Path(directory)
    need(directory.is_absolute() and directory.is_dir() and {p.name for p in directory.iterdir()} == ASSETS,
         "exact three-asset directory required")
    for name in ASSETS:
        regular(directory / name)
    expected = candidate(request, archive_override=directory / ARCHIVE)
    stage("DESCRIPTOR")
    description = bounded_bytes(directory / "candidate-build.json", 65536)
    need(description == canonical(expected), "local descriptor differs or contains hosted/unknown fields")
    checksum = (request["archive"]["sha256"] + "  " + ARCHIVE + "\n").encode()
    need(bounded_bytes(directory / (ARCHIVE + ".sha256"), 4096) == checksum, "checksum asset differs")
    assets = [{"name": name, "bytes": (directory / name).stat().st_size,
               "sha256": request["archive"]["sha256"] if name == ARCHIVE else file_sha(directory / name)}
              for name in sorted(ASSETS)]
    return {"protocol": VERIFICATION_PROTOCOL, "tag": tag_for(request),
            "control_commit": request["control"]["commit"], "archive_sha256": request["archive"]["sha256"],
            "version": request["version"], "assets": assets}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    create = sub.add_parser("create")
    create.add_argument("--request", required=True)
    create.add_argument("--output", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--request", required=True)
    check.add_argument("--asset-dir", required=True)
    args = parser.parse_args()
    try:
        request = load_request(args.request)
        if args.operation == "verify":
            result = verify(request, args.asset_dir)
        else:
            output = Path(args.output)
            need(output.is_absolute() and output.name == "candidate-build.json", "fixed descriptor output required")
            body = canonical(candidate(request))
            stage("DESCRIPTOR")
            with output.open("xb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            need(bounded_bytes(output) == body, "descriptor write verification failed")
            result = {"protocol": "tden:node-local-candidate-created:v1", "tag": tag_for(request),
                      "candidate_sha256": digest(body)}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (ValueError, KeyError, TypeError, OSError, EOFError, tarfile.TarError, subprocess.SubprocessError):
        # Never echo local paths, environment, raw receipts or tool diagnostics.
        parser.exit(1, "LOCAL_CANDIDATE_" + ERROR_STAGE + "\n")


if __name__ == "__main__":
    main()
