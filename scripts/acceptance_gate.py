"""Fail-closed stable gate for attested, exact-archive deployment acceptance."""

import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from tempfile import TemporaryDirectory

from candidate_metadata import decode, file_sha, hex_value, read_json, require


REQUIRED_IDS = tuple(
    f"{prefix}{number:02d}"
    for prefix, count in (("D", 18), ("H", 10), ("R", 12), ("U", 17))
    for number in range(1, count + 1)
)
ARTIFACT = "node-deployment-acceptance"
MANIFEST = "acceptance-manifest.json"
WORKFLOW_PATTERN = r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml"


def utc(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", value),
            "timestamp must be UTC ISO-8601")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def positive_int(value):
    return type(value) is int and value > 0


def source_policy(policy, release_repository):
    require(isinstance(policy, dict) and set(policy) ==
            {"protocol", "max_age_days", "required_test_ids", "trusted_source"}, "acceptance policy fields invalid")
    require(policy["protocol"] == "tden:node-acceptance-policy:v1", "acceptance policy protocol invalid")
    require(policy["required_test_ids"] == list(REQUIRED_IDS), "required acceptance tests cannot be reduced")
    require(type(policy["max_age_days"]) is int and 1 <= policy["max_age_days"] <= 30,
            "acceptance freshness policy invalid")
    source = policy["trusted_source"]
    require(source is not None, "stable blocked: no reviewed, trusted deployment acceptance source is configured")
    require(isinstance(source, dict) and set(source) == {"repository", "workflow", "commit"},
            "trusted acceptance source fields invalid")
    require(source["repository"] == release_repository, "acceptance source must be this release repository")
    require(isinstance(source["workflow"], str) and re.fullmatch(WORKFLOW_PATTERN, source["workflow"])
            and source["workflow"] not in (".github/workflows/build-node-candidate.yml",
                                           ".github/workflows/promote-node-candidate.yml"),
            "trusted acceptance workflow path invalid")
    require(hex_value(source["commit"], 40), "trusted acceptance workflow commit invalid")
    return source


def verify_run(run, workflow, source, requested_id):
    require(run.get("id") == requested_id and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed" and run.get("conclusion") == "success",
            "acceptance run is not the requested successful dispatch")
    require(run.get("head_repository", {}).get("full_name") == source["repository"]
            and run.get("head_sha") == source["commit"] and positive_int(run.get("run_attempt")),
            "acceptance run repository/commit/attempt mismatch")
    require(workflow.get("id") == run.get("workflow_id") and workflow.get("path") == source["workflow"],
            "acceptance workflow identity mismatch")
    require(utc(run["created_at"]) <= utc(run["updated_at"]), "acceptance run timestamps invalid")


def verify_receipt(receipts, manifest_sha, run, source):
    invocation = (f"https://github.com/{source['repository']}/actions/runs/{run['id']}"
                  f"/attempts/{run['run_attempt']}")
    signer = f"https://github.com/{source['repository']}/{source['workflow']}@"
    require(isinstance(receipts, list), "acceptance attestation verifier output invalid")
    for record in receipts:
        result = record["verificationResult"]
        cert = result["signature"]["certificate"]
        if cert.get("runInvocationURI") != invocation:
            continue
        require(cert.get("issuer") == "https://token.actions.githubusercontent.com"
                and cert.get("buildSignerURI", "").startswith(signer)
                and cert.get("sourceRepositoryDigest") == source["commit"]
                and cert.get("buildSignerDigest") == source["commit"],
                "acceptance attestation signer mismatch")
        require(cert.get("runnerEnvironment") == "github-hosted" and result.get("verifiedTimestamps"),
                "acceptance attestation has no hosted runner or verified timestamp")
        statement = result["statement"]
        require(statement.get("_type") == "https://in-toto.io/Statement/v1"
                and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
                and statement.get("subject") == [{"name": MANIFEST, "digest": {"sha256": manifest_sha}}]
                and statement["predicate"]["runDetails"]["metadata"]["invocationId"] == invocation,
                "acceptance attestation subject/invocation mismatch")
        return
    raise ValueError("no verified attestation for the exact acceptance run/attempt")


def verify_evidence(root, test_id, evidence):
    require(isinstance(evidence, list) and evidence, f"{test_id}: evidence missing")
    paths = set()
    for item in evidence:
        require(isinstance(item, dict) and set(item) == {"path", "sha256"},
                f"{test_id}: evidence entry invalid")
        name = item["path"]
        require(isinstance(name, str) and name.startswith(f"evidence/{test_id}/")
                and all(part not in ("", ".", "..") for part in PurePosixPath(name).parts)
                and re.fullmatch(r"[A-Za-z0-9._/-]+", name) and name not in paths,
                f"{test_id}: unsafe or duplicate evidence path")
        require(hex_value(item["sha256"], 64), f"{test_id}: evidence digest invalid")
        path = root.joinpath(*PurePosixPath(name).parts)
        require(path.is_file() and not any(part.is_symlink() for part in (path, *path.parents) if part != root.parent)
                and path.resolve().is_relative_to(root.resolve()), f"{test_id}: evidence file missing or unsafe")
        require(file_sha(path) == item["sha256"], f"{test_id}: evidence digest mismatch")
        paths.add(name)
    return paths


def verify_manifest(manifest, candidate, candidate_run, candidate_build_sha, run, jobs, root, policy, now):
    fields = {"protocol", "archive_sha256", "candidate_run_id", "candidate_run_attempt",
              "candidate_build_sha256", "source_commits", "runtime_bundle", "network_id",
              "environment", "promotable", "unresolved_blockers", "started_at_utc",
              "finished_at_utc", "results"}
    require(isinstance(manifest, dict) and set(manifest) == fields, "acceptance manifest fields invalid")
    require(manifest["protocol"] == "tden:node-deployment-acceptance:v1", "acceptance protocol invalid")
    require(isinstance(candidate.get("runtime_bundle"), dict),
            "stable requires a runtime candidate with separately attested build description")
    require(manifest["archive_sha256"] == candidate["archive_sha256"]
            and manifest["candidate_run_id"] == candidate_run["id"]
            and manifest["candidate_run_attempt"] == candidate_run["run_attempt"]
            and manifest["candidate_build_sha256"] == candidate_build_sha,
            "acceptance does not bind the exact attested candidate")
    require(manifest["source_commits"] == {key: candidate[key] for key in
            ("chain_commit", "gateway_commit", "deploy_commit")}, "acceptance source commits mismatch")
    require(manifest["runtime_bundle"] == candidate.get("runtime_bundle"),
            "acceptance manifest/profile binding mismatch")
    require(isinstance(manifest["network_id"], str) and 1 <= len(manifest["network_id"]) <= 128
            and isinstance(manifest["environment"], str) and 1 <= len(manifest["environment"]) <= 128,
            "acceptance network/environment missing")
    require(manifest["promotable"] is True and manifest["unresolved_blockers"] == [],
            "derived package or unresolved blocker cannot be promoted")
    started, finished = utc(manifest["started_at_utc"]), utc(manifest["finished_at_utc"])
    require(utc(candidate_run["created_at"]) <= started <= finished <= utc(run["updated_at"])
            and finished <= now and now - finished <= timedelta(days=policy["max_age_days"]),
            "acceptance is stale, premature or outside the workflow run")
    require(isinstance(jobs, list) and jobs and all(isinstance(page, dict) and isinstance(page.get("jobs"), list)
            for page in jobs), "acceptance jobs response invalid")
    relevant = [job for page in jobs for job in page["jobs"]
                if isinstance(job, dict) and job.get("name") in {f"accept-{test}" for test in REQUIRED_IDS}]
    require(len(relevant) == len(REQUIRED_IDS)
            and {job.get("name") for job in relevant} == {f"accept-{test}" for test in REQUIRED_IDS},
            "required independent acceptance jobs missing or duplicated")
    by_id = {job.get("id"): job for job in relevant}
    require(len(by_id) == len(REQUIRED_IDS), "acceptance job IDs duplicated")
    results = manifest["results"]
    require(isinstance(results, list) and len(results) == len(REQUIRED_IDS),
            "required acceptance results missing or extra")
    seen, referenced = set(), {MANIFEST}
    for result in results:
        require(isinstance(result, dict) and set(result) ==
                {"test_id", "status", "job_id", "archive_sha256", "started_at_utc", "finished_at_utc", "evidence"},
                "acceptance result fields invalid")
        test_id = result["test_id"]
        require(test_id in REQUIRED_IDS and test_id not in seen, "unexpected or duplicate acceptance test ID")
        seen.add(test_id)
        require(result["status"] == "PASS" and result["archive_sha256"] == manifest["archive_sha256"],
                f"{test_id}: not PASS on the original archive")
        require(positive_int(result["job_id"]), f"{test_id}: job ID invalid")
        job = by_id.get(result["job_id"])
        require(job is not None and job.get("name") == f"accept-{test_id}"
                and job.get("run_id") == run["id"] and job.get("head_sha") == run["head_sha"]
                and job.get("status") == "completed" and job.get("conclusion") == "success",
                f"{test_id}: independent acceptance job did not succeed")
        item_start, item_finish = utc(result["started_at_utc"]), utc(result["finished_at_utc"])
        require(started <= item_start <= item_finish <= finished
                and utc(job["started_at"]) <= item_start <= item_finish <= utc(job["completed_at"]),
                f"{test_id}: result timestamp outside successful job")
        paths = verify_evidence(root, test_id, result["evidence"])
        require(not referenced.intersection(paths), f"{test_id}: evidence reused")
        referenced.update(paths)
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    require(actual == referenced and not any(path.is_symlink() for path in root.rglob("*")),
            "acceptance artifact contains unreferenced or unsafe files")


def gh(*args):
    return subprocess.check_output(("gh", *args), text=True)


def verify(args):
    repository = os.environ["GITHUB_REPOSITORY"]
    policy = read_json(args.policy)
    source = source_policy(policy, repository)
    require(isinstance(args.acceptance_run_id, str) and re.fullmatch(r"[1-9][0-9]*", args.acceptance_run_id),
            "stable requires a trusted acceptance workflow run ID")
    run_id = int(args.acceptance_run_id)
    run = decode(gh("api", f"repos/{repository}/actions/runs/{run_id}"))
    workflow = decode(gh("api", f"repos/{repository}/actions/workflows/{run['workflow_id']}"))
    verify_run(run, workflow, source, run_id)
    jobs = decode(gh("api", "--paginate", "--slurp",
                     f"repos/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs?per_page=100"))
    candidate = read_json(args.candidate)
    candidate_run = read_json(args.candidate_run)
    require(isinstance(candidate.get("runtime_bundle"), dict),
            "stable requires a runtime candidate with separately attested build description")
    require(candidate["archive_sha256"] == os.environ["EXPECTED_SHA256"], "candidate digest mismatch")
    with TemporaryDirectory() as directory:
        root = Path(directory) / "acceptance"
        root.mkdir()
        gh("run", "download", str(run_id), "--repo", repository,
           "--name", ARTIFACT, "--dir", str(root))
        manifest_path = root / MANIFEST
        require(manifest_path.is_file() and not manifest_path.is_symlink(), "acceptance manifest missing")
        receipt = decode(gh("attestation", "verify", str(manifest_path), "--repo", repository,
                            "--signer-workflow", f"{repository}/{source['workflow']}",
                            "--signer-digest", source["commit"], "--source-digest", source["commit"],
                            "--deny-self-hosted-runners", "--format", "json"))
        verify_receipt(receipt, file_sha(manifest_path), run, source)
        manifest = read_json(manifest_path)
        verify_manifest(manifest, candidate, candidate_run, file_sha(args.candidate),
                        run, jobs, root, policy, datetime.now(timezone.utc))
        with Path(args.output).open("a", encoding="utf-8") as output:
            output.write(f"run_id={run_id}\nmanifest_sha256={file_sha(manifest_path)}\n")
        print(f"PASS: exact-archive stable acceptance from trusted run {run_id}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="acceptance-policy.json")
    parser.add_argument("--candidate", default="candidate/candidate-build.json")
    parser.add_argument("--candidate-run", default="run.json")
    parser.add_argument("--acceptance-run-id", default="")
    parser.add_argument("--output", default=os.environ.get("GITHUB_OUTPUT", os.devnull))
    args = parser.parse_args()
    try:
        verify(args)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"stable acceptance blocked: {error}\n")


if __name__ == "__main__":
    main()
