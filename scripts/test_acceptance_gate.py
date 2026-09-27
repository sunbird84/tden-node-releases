import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import acceptance_gate as gate
from candidate_metadata import file_sha, sha


class AcceptanceGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = datetime.now(timezone.utc)
        self.repo = "sunbird84/tden-node-releases"
        self.source = {
            "repository": self.repo,
            "workflow": ".github/workflows/fixture-only-acceptance.yml",
            "commit": "a" * 40,
        }
        self.policy = {
            "protocol": "tden:node-acceptance-policy:v1", "max_age_days": 30,
            "required_test_ids": list(gate.REQUIRED_IDS), "trusted_source": self.source,
        }
        self.candidate = {
            "archive_sha256": "b" * 64, "chain_commit": "1" * 40,
            "gateway_commit": "2" * 40, "deploy_commit": "3" * 40,
            "runtime_bundle": {"package_manifest_sha256": "c" * 64,
                               "configuration_profile_sha256": "d" * 64},
        }
        self.candidate_build_sha = "e" * 64
        self.candidate_run = {"id": 123, "run_attempt": 2, "created_at": self.ts(-4)}
        self.run = {
            "id": 456, "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
            "head_repository": {"full_name": self.repo}, "head_sha": self.source["commit"],
            "run_attempt": 3, "workflow_id": 789, "created_at": self.ts(-3),
            "updated_at": self.ts(0),
        }
        self.workflow = {"id": 789, "path": self.source["workflow"]}
        self.jobs = [{"jobs": []}]
        results = []
        for index, test_id in enumerate(gate.REQUIRED_IDS, 1):
            path = f"evidence/{test_id}/result.json"
            body = ("evidence for " + test_id).encode()
            target = self.root / path
            target.parent.mkdir(parents=True)
            target.write_bytes(body)
            self.jobs[0]["jobs"].append({
                "id": index, "run_id": self.run["id"], "head_sha": self.run["head_sha"],
                "name": f"accept-{test_id}", "status": "completed", "conclusion": "success",
                "started_at": self.ts(-2), "completed_at": self.ts(-1, 30),
            })
            results.append({
                "test_id": test_id, "status": "PASS", "job_id": index,
                "archive_sha256": self.candidate["archive_sha256"],
                "started_at_utc": self.ts(-2), "finished_at_utc": self.ts(-1, 20),
                "evidence": [{"path": path, "sha256": sha(body)}],
            })
        self.manifest = {
            "protocol": "tden:node-deployment-acceptance:v1",
            "archive_sha256": self.candidate["archive_sha256"],
            "candidate_run_id": self.candidate_run["id"],
            "candidate_run_attempt": self.candidate_run["run_attempt"],
            "candidate_build_sha256": self.candidate_build_sha,
            "source_commits": {key: self.candidate[key] for key in
                               ("chain_commit", "gateway_commit", "deploy_commit")},
            "runtime_bundle": self.candidate["runtime_bundle"],
            "network_id": "isolated-test-network", "environment": "isolated-real-linux",
            "promotable": True, "unresolved_blockers": [],
            "started_at_utc": self.ts(-2), "finished_at_utc": self.ts(-1, 20),
            "results": results,
        }
        (self.root / gate.MANIFEST).write_text(json.dumps(self.manifest), encoding="utf-8")

    def ts(self, hours, minutes=0):
        return (self.now + timedelta(hours=hours, minutes=minutes)).isoformat().replace("+00:00", "Z")

    def check(self, manifest=None, jobs=None, policy=None, now=None):
        gate.verify_manifest(manifest or self.manifest, self.candidate, self.candidate_run,
                             self.candidate_build_sha, self.run, jobs or self.jobs,
                             self.root, policy or self.policy, now or self.now)

    def receipt(self):
        invocation = (f"https://github.com/{self.repo}/actions/runs/{self.run['id']}"
                      f"/attempts/{self.run['run_attempt']}")
        return [{"verificationResult": {
            "signature": {"certificate": {
                "runInvocationURI": invocation,
                "issuer": "https://token.actions.githubusercontent.com",
                "buildSignerURI": f"https://github.com/{self.repo}/{self.source['workflow']}@refs/heads/main",
                "sourceRepositoryDigest": self.source["commit"],
                "buildSignerDigest": self.source["commit"], "runnerEnvironment": "github-hosted",
            }},
            "verifiedTimestamps": [{"type": "fixture-only"}],
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": gate.MANIFEST, "digest": {"sha256": "f" * 64}}],
                "predicate": {"runDetails": {"metadata": {"invocationId": invocation}}},
            },
        }}]

    def test_complete_contract_passes_parser_only(self):
        gate.source_policy(self.policy, self.repo)
        gate.verify_run(self.run, self.workflow, self.source, self.run["id"])
        gate.verify_receipt(self.receipt(), "f" * 64, self.run, self.source)
        self.check()

    def test_verify_fetches_trusted_run_and_attested_artifact(self):
        candidate_path = self.root / "candidate.json"
        candidate_run_path = self.root / "run.json"
        policy_path = self.root / "policy.json"
        output_path = self.root / "output.txt"
        candidate_path.write_text(json.dumps(self.candidate), encoding="utf-8")
        candidate_run_path.write_text(json.dumps(self.candidate_run), encoding="utf-8")
        policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.manifest["candidate_build_sha256"] = file_sha(candidate_path)
        (self.root / gate.MANIFEST).write_text(json.dumps(self.manifest), encoding="utf-8")
        receipt = self.receipt()
        receipt[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = file_sha(self.root / gate.MANIFEST)
        calls = []

        def fake_gh(*args):
            calls.append(args)
            if args[:2] == ("api", f"repos/{self.repo}/actions/runs/456"):
                return json.dumps(self.run)
            if args[:2] == ("api", f"repos/{self.repo}/actions/workflows/789"):
                return json.dumps(self.workflow)
            if args[:2] == ("api", "--paginate"):
                return json.dumps(self.jobs)
            if args[:2] == ("run", "download"):
                target = Path(args[args.index("--dir") + 1])
                shutil.copy2(self.root / gate.MANIFEST, target / gate.MANIFEST)
                shutil.copytree(self.root / "evidence", target / "evidence")
                return ""
            if args[:2] == ("attestation", "verify"):
                self.assertIn("--deny-self-hosted-runners", args)
                self.assertEqual(args[args.index("--signer-digest") + 1], self.source["commit"])
                return json.dumps(receipt)
            self.fail(f"unexpected GitHub request: {args}")

        args = SimpleNamespace(policy=policy_path, candidate=candidate_path,
                               candidate_run=candidate_run_path, acceptance_run_id="456",
                               output=output_path)
        with (
            patch.dict(os.environ, {"GITHUB_REPOSITORY": self.repo,
                                     "EXPECTED_SHA256": self.candidate["archive_sha256"]}),
            patch.object(gate, "gh", side_effect=fake_gh),
            patch("builtins.print"),
        ):
            gate.verify(args)
        self.assertIn("run_id=456", output_path.read_text(encoding="utf-8"))
        self.assertEqual([call[:2] for call in calls],
                         [("api", f"repos/{self.repo}/actions/runs/456"),
                          ("api", f"repos/{self.repo}/actions/workflows/789"),
                          ("api", "--paginate"), ("run", "download"),
                          ("attestation", "verify")])

    def test_unconfigured_source_and_reduced_tests_fail_closed(self):
        policy = copy.deepcopy(self.policy)
        policy["trusted_source"] = None
        with self.assertRaisesRegex(ValueError, "no reviewed"):
            gate.source_policy(policy, self.repo)
        policy["trusted_source"] = self.source
        policy["required_test_ids"].remove("D16")
        with self.assertRaisesRegex(ValueError, "cannot be reduced"):
            gate.source_policy(policy, self.repo)
        policy = copy.deepcopy(self.policy)
        policy["trusted_source"]["repository"] = "attacker/repo"
        with self.assertRaises(ValueError):
            gate.source_policy(policy, self.repo)

    def test_wrong_run_workflow_commit_attempt_or_result_fails(self):
        for key, value in (("id", 457), ("conclusion", "failure"),
                           ("head_sha", "0" * 40), ("event", "push")):
            changed = copy.deepcopy(self.run)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.verify_run(changed, self.workflow, self.source, 456)
        with self.assertRaises(ValueError):
            gate.verify_run(self.run, {"id": 789, "path": "other.yml"}, self.source, 456)

    def test_attestation_is_bound_to_run_attempt_signer_and_subject(self):
        for field, value in (("runInvocationURI", "wrong"), ("sourceRepositoryDigest", "0" * 40),
                             ("buildSignerURI", "https://github.com/attacker/workflow@main"),
                             ("runnerEnvironment", "self-hosted")):
            changed = self.receipt()
            changed[0]["verificationResult"]["signature"]["certificate"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.verify_receipt(changed, "f" * 64, self.run, self.source)
        with self.assertRaisesRegex(ValueError, "subject"):
            gate.verify_receipt(self.receipt(), "0" * 64, self.run, self.source)

    def test_wrong_candidate_or_derived_package_fails(self):
        for key, value in (("archive_sha256", "0" * 64), ("candidate_run_id", 122),
                           ("candidate_run_attempt", 1), ("candidate_build_sha256", "0" * 64),
                           ("runtime_bundle", None), ("promotable", False),
                           ("unresolved_blockers", ["D07"])):
            changed = copy.deepcopy(self.manifest)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(manifest=changed)
        changed = copy.deepcopy(self.manifest)
        changed["source_commits"]["deploy_commit"] = "0" * 40
        with self.assertRaises(ValueError):
            self.check(manifest=changed)
        saved = self.candidate.pop("runtime_bundle")
        with self.assertRaisesRegex(ValueError, "separately attested"):
            self.check()
        self.candidate["runtime_bundle"] = saved

    def test_missing_extra_failed_blocked_or_skipped_test_fails(self):
        for status in ("FAIL", "BLOCKED", "NOT_RUN", "SKIPPED", "pass"):
            changed = copy.deepcopy(self.manifest)
            changed["results"][0]["status"] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.check(manifest=changed)
        changed = copy.deepcopy(self.manifest)
        changed["results"].pop()
        with self.assertRaises(ValueError):
            self.check(manifest=changed)
        changed = copy.deepcopy(self.manifest)
        changed["results"][1] = changed["results"][0]
        with self.assertRaises(ValueError):
            self.check(manifest=changed)

    def test_failed_or_missing_independent_job_fails(self):
        for key, value in (("conclusion", "skipped"), ("status", "in_progress"),
                           ("run_id", 999), ("head_sha", "0" * 40)):
            jobs = copy.deepcopy(self.jobs)
            jobs[0]["jobs"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(jobs=jobs)
        jobs = copy.deepcopy(self.jobs)
        jobs[0]["jobs"].pop()
        with self.assertRaises(ValueError):
            self.check(jobs=jobs)

    def test_stale_or_impossible_timestamps_fail(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check(now=self.now + timedelta(days=31))
        changed = copy.deepcopy(self.manifest)
        changed["results"][0]["finished_at_utc"] = self.ts(0)
        with self.assertRaises(ValueError):
            self.check(manifest=changed)
        changed = copy.deepcopy(self.manifest)
        changed["started_at_utc"] = self.ts(-5)
        with self.assertRaises(ValueError):
            self.check(manifest=changed)

    def test_missing_replaced_or_unsafe_evidence_fails(self):
        target = self.root / "evidence/D01/result.json"
        target.write_bytes(b"replaced")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.check()
        target.unlink()
        with self.assertRaises(ValueError):
            self.check()
        target.write_bytes(b"evidence for D01")
        changed = copy.deepcopy(self.manifest)
        changed["results"][0]["evidence"][0]["path"] = "evidence/D01/../../escape"
        with self.assertRaises(ValueError):
            self.check(manifest=changed)
        (self.root / "unlisted.json").write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "unreferenced"):
            self.check()

    def test_workflow_places_stable_gate_before_publication(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/promote-node-candidate.yml").read_text(encoding="utf-8")
        self.assertLess(workflow.index("Require trusted deployment acceptance for stable"),
                        workflow.index("Publish the exact archive without rebuilding"))
        self.assertIn("if: inputs.release_channel == 'stable'", workflow)
        self.assertIn("python3 scripts/acceptance_gate.py --acceptance-run-id", workflow)


if __name__ == "__main__":
    unittest.main()
