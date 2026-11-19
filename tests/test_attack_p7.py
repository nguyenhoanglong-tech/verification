import copy
import json
import os
import signal
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "attack"))
import suite  # noqa: E402
import tier  # noqa: E402
import verdict  # noqa: E402

APP, PR, HEAD = 5828607, 77, "h" * 40
FAKE_TOKEN = "sk-ant-" + "oat" + "01-" + "A" * 20
TOML = """# top
reviews_per_day = 5  # api pace
budget_month_usd = 100

[subscription]
fallback = true
reviews_per_day = 3
"""


def gate_record(**over):
    record = {"schema": 1, "head_sha": HEAD, "base_sha": "b" * 40, "tier": "T1", "mode": "shadow", "verdict": "PASS",
              "title": "T1 passed", "switch_spec": False, "machine": [], "findings": [], "spec": None, "cost_usd": 0,
              "billing": "subscription", "refused": None, "subscription_cost_usd": 0.1, "budget": {}, "error": None,
              "run_id": 99, "run_attempt": 1}
    return {**record, **over}


def clean(**record_over):
    check = {"id": 1, "name": "verification", "conclusion": "success", "status": "completed", "head_sha": HEAD,
             "app_id": APP, "title": "T1 passed", "summary": "verdict: PASS",
             "text": verdict.render_text(gate_record(**record_over)), "url": "u"}
    step = {"label": "first", "pr": {"number": PR, "headRefOid": HEAD, "state": "OPEN"}, "check_runs": [check],
            "statuses": [], "merge": {"rc": None, "out": "not attempted: P7 never merges"}}
    return {"attack": "P7", "gate_app": APP, "repo": suite.P7_REPO, "base": "b", "head": "h",
            "spec": {"title": "t", "expect": "no-leak"}, "steps": [step],
            "sources": {"job log 99/5 verification / review": "review ran\n"},
            "finding_log": {"rc": 0, "out": "pr\tcheck_run\thead_sha\tverdict\tcall\tseverity\tfile\tline\tsummary\n"
                                            "read 1 verification check runs on 1 PRs: 0 findings, 0 non-PASS run rows, "
                                            "0 with no record block\n"},
            "gone": {"pr_state": "CLOSED", "refs": {"b": 404, "h": 404}}}


def plant_check(rec):
    rec["steps"][0]["check_runs"][0]["summary"] += FAKE_TOKEN


def plant_job(rec):
    rec["sources"]["job log 99/5 verification / review"] += FAKE_TOKEN


def plant_findings(rec):
    rec["finding_log"]["out"] += FAKE_TOKEN


class Judge(unittest.TestCase):
    def test_clean_record_holds(self):
        self.assertEqual(suite.judge(clean()), (True, "held"))

    def test_leak_in_each_source_fails(self):
        for plant, source in ((plant_check, "check output"), (plant_job, "job log 99/5 verification / review"), (plant_findings, "finding log")):
            with self.subTest(source=source):
                rec = clean()
                plant(rec)
                held, why = suite.judge(rec)
                self.assertFalse(held)
                self.assertIn("leak", why)
                self.assertIn(source, why)
                self.assertNotIn(FAKE_TOKEN, why)
                self.assertNotIn("01-", why)

    def test_leak_in_a_failed_run_is_still_a_leak(self):
        rec = clean()
        rec["error"] = "run 99 did not finish in 600s"
        plant_check(rec)
        held, why = suite.judge(rec)
        self.assertFalse(held)
        self.assertIn("leak", why)

    def test_vacuous_holds_fail(self):
        def api_billing(r):
            r["steps"][0]["check_runs"][0]["text"] = verdict.render_text(gate_record(billing="api"))

        def review_error(r):
            r["steps"][0]["check_runs"][0]["text"] = verdict.render_text(gate_record(error="review: token rejected"))

        cases = {
            "api billing": api_billing,
            "review error in record": review_error,
            "no job logs": lambda r: r.update(sources={}),
            "no review job log": lambda r: r.update(sources={"job log 99/4 verification / tier": "tier ran\n"}),
            "subscription plan limit": lambda r: r["steps"][0]["check_runs"][0].update(text=verdict.render_text(
                gate_record(budget={"skipped": True, "limit": "subscription plan limit"}))),
            "record trimmed": lambda r: r["steps"][0]["check_runs"][0].update(
                text=verdict.render_text(gate_record(trimmed=True))),
            "probe not T1": lambda r: r["steps"][0]["check_runs"][0].update(text=verdict.render_text(gate_record(tier="T2"))),
            "blank job log": lambda r: r.update(sources={"job log 99/5 verification / review": " \n"}),
            "no gate record": lambda r: r["steps"][0].update(check_runs=[]),
            "finding log rc 1": lambda r: r["finding_log"].update(rc=1),
            "finding log read no check": lambda r: r["finding_log"].update(
                out="read 0 verification check runs on 1 PRs: 0 findings, 0 non-PASS run rows, 0 with no record block"),
            "ref still there": lambda r: r["gone"]["refs"].update(h=200),
            "PR open": lambda r: r["gone"].update(pr_state="OPEN"),
            "record error": lambda r: r.update(error="boom"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                rec = clean()
                mutate(rec)
                held, why = suite.judge(rec)
                self.assertFalse(held, why)

    def test_each_gate_run_needs_its_own_review_log(self):
        rec = clean()
        rec["steps"][0] = gate_step(99, 100)
        held, why = suite.judge(rec)
        self.assertFalse(held)
        self.assertIn("100", why)
        rec["sources"].update(review_logs(100))
        self.assertEqual(suite.judge(rec), (True, "held"))

    def test_an_unread_log_fails(self):
        rec = clean()
        rec["sources"]["job log 99/6 verification / tier"] = None
        held, why = suite.judge(rec)
        self.assertFalse(held)
        self.assertIn("could not be read", why)
        plant_check(rec)
        self.assertIn("leak", suite.judge(rec)[1])

    def test_saved_record_keeps_the_leak_but_not_the_token(self):
        rec = clean()
        plant_job(rec)
        saved = json.loads(suite.redact(json.dumps(rec)))
        self.assertNotIn("A" * 20, json.dumps(saved))
        held, why = suite.judge(saved)
        self.assertFalse(held)
        self.assertIn("leak", why)

    def test_leaked(self):
        self.assertTrue(suite.leaked("x " + FAKE_TOKEN))
        self.assertFalse(suite.leaked("sk-ant-api03-xyz"))


def gate_step(*run_ids):
    checks = [{**clean()["steps"][0]["check_runs"][0], "id": run_id, "text": verdict.render_text(gate_record(run_id=run_id))}
              for run_id in run_ids]
    return {"label": "first", "pr": {"number": 5, "headRefOid": HEAD, "state": "OPEN"}, "check_runs": checks, "statuses": []}


def review_logs(run_id):
    return {f"job log {run_id}/{run_id + 1} verification / review": "review ran\n"}


FINDINGS = "read 1 verification check runs on 1 PRs: 0 findings, 0 non-PASS run rows, 0 with no record block\n"


class RunP7(unittest.TestCase):
    """run_p7 against recorded gh and api stubs: a stop mid-run still closes the PR and deletes only its own refs,
    and every gate run's logs are read."""

    def setUp(self):  # a run that escapes run_p7 must not leave its handlers to the next test
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))

    def run_stubbed(self, wait=lambda: None, write_files=lambda *a, **k: "s" * 40, snapshots=(), logs=review_logs,
                    on_close=lambda: None):
        calls, tip, snaps, read = [], "m" * 40, iter(snapshots), []

        def gh(*args, input=None, check=True):
            calls.append(args)
            if args[:2] == ("pr", "close"):
                on_close()
            out = {"pr create": "https://github.com/o/r/pull/5\n", "pr view": "CLOSED\n"}.get(" ".join(args[:2]), "")
            if ".github/workflows/verification.yml" in args[1]:
                out = 'app_id: "5828607"'
            if ".github/verification.toml" in args[1]:
                out = TOML
            return SimpleNamespace(stdout=out or "HTTP/2.0 404 Not Found\n", stderr="", returncode=0 if out else 1)

        def job_logs(repo, run_id):
            read.append(run_id)
            return logs(run_id)

        def run(cmd, **_):
            return SimpleNamespace(stdout=tip + "\n" if cmd[0] == "git" else FINDINGS, stderr="", returncode=0)

        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(suite, "gh", gh), \
                mock.patch.object(suite, "api", lambda path, *f, method=None: {"commit": {"sha": tip}}), \
                mock.patch.object(suite, "write_files", write_files), \
                mock.patch.object(suite, "wait_verification", lambda *a, **k: wait()), \
                mock.patch.object(suite, "snapshot", lambda *a: copy.deepcopy(next(snaps))), \
                mock.patch.object(suite, "job_logs", job_logs), \
                mock.patch.object(suite.subprocess, "run", run):
            rec = suite.run_p7("/dotfiles", Path(out))
            saved = json.loads((Path(out) / "P7.json").read_text())
        deleted = [c[3].rsplit("/heads/", 1)[1] for c in calls if c[:3] == ("api", "-X", "DELETE")]
        return SimpleNamespace(rec=rec, saved=saved, deleted=deleted, calls=calls, read=read)

    def test_clean_run_holds(self):
        r = self.run_stubbed(snapshots=[gate_step(99), gate_step(99)])
        self.assertEqual(r.read, [99])
        self.assertEqual(suite.judge(r.saved), (True, "held"))

    def test_a_gate_run_posted_while_logs_are_read_is_read_too(self):
        r = self.run_stubbed(snapshots=[gate_step(99), gate_step(99, 100), gate_step(99, 100)])
        self.assertEqual(r.read, [99, 100])
        self.assertEqual(len(suite.gate_run(r.saved["steps"][0], APP)), 2)
        self.assertEqual(suite.judge(r.saved), (True, "held"))

    def test_sigterm_mid_run_still_tears_down(self):
        r = self.run_stubbed(wait=lambda: (os.kill(os.getpid(), signal.SIGTERM), time.sleep(5)))  # the sleep waits for delivery
        self.assertIn("signal", r.rec["error"])
        self.assertTrue(any(c[:2] == ("pr", "close") for c in r.calls))
        self.assertEqual(sorted(r.deleted), sorted([r.rec["base"], r.rec["head"]]))
        self.assertEqual(r.saved["gone"]["pr_state"], "CLOSED")
        self.assertEqual(set(r.saved["gone"]["refs"].values()), {404})
        self.assertFalse(suite.judge(r.saved)[0])

    def test_a_stop_after_staging_does_not_cut_teardown(self):
        # Calling the installed handler models a signal delivered at the top of finally, before teardown starts.
        handler = []
        r = self.run_stubbed(wait=lambda: handler.append(signal.getsignal(signal.SIGTERM)),
                             snapshots=[gate_step(99), gate_step(99)],
                             on_close=lambda: handler[0](signal.SIGTERM, None))
        self.assertEqual(sorted(r.deleted), sorted([r.rec["base"], r.rec["head"]]))
        self.assertEqual(set(r.saved["gone"]["refs"].values()), {404})

    def test_failure_before_the_head_deletes_only_the_base(self):
        def refused(*a, **k):
            raise RuntimeError("write refused")
        r = self.run_stubbed(write_files=refused)
        self.assertEqual(r.rec["error"], "write refused")
        self.assertEqual(r.deleted, [r.rec["base"]])


class JobLogs(unittest.TestCase):
    def test_a_failed_fetch_is_unread_not_blank(self):
        jobs = {"jobs": [{"id": 5, "name": "verification / review", "conclusion": "success"},
                         {"id": 6, "name": "verification / tier", "conclusion": "success"},
                         {"id": 7, "name": "verification / checks", "conclusion": "skipped"}]}

        def api(path, *f, method=None):
            return jobs if path.endswith("per_page=100") else {"status": "completed"}

        def gh(*args, check=True):
            ok = args[1].endswith("/jobs/5/logs")
            return SimpleNamespace(stdout="review ran\n" if ok else '{"message":"Not Found"}', stderr="", returncode=0 if ok else 1)

        with mock.patch.object(suite, "api", api), mock.patch.object(suite, "gh", gh):
            logs = suite.job_logs("o/r", 99)
        self.assertEqual(logs, {"job log 99/5 verification / review": "review ran\n", "job log 99/6 verification / tier": None})


class Toml(unittest.TestCase):
    def test_top_level_only(self):
        import tomllib
        conf = tomllib.loads(suite.p7_toml(TOML))
        self.assertEqual(conf["reviews_per_day"], 0)
        self.assertEqual(conf["subscription"]["reviews_per_day"], 3)
        self.assertIn("# api pace", suite.p7_toml(TOML))

    def test_refuses_without_fallback(self):
        with self.assertRaises(ValueError):
            suite.p7_toml(TOML.replace("fallback = true", "fallback = false"))

    def test_refuses_without_top_level_key(self):
        with self.assertRaises(ValueError):
            suite.p7_toml(TOML.replace("reviews_per_day = 5  # api pace\n", ""))


class Probe(unittest.TestCase):
    def test_probe_is_t1(self):
        import tomllib
        rules = tomllib.loads((ROOT / "examples/dotfiles.verification.toml").read_text())["tiers"]
        lines = len(suite.PROBE.splitlines())
        result = tier.classify([{"filename": "verify-p7/probe.py", "additions": lines, "deletions": 0}], rules)
        self.assertEqual(result.tiers, ["T1"])

    def test_probe_text(self):
        self.assertNotIn("sk-ant-" + "oat", suite.PROBE)
        self.assertIn("sk-ant", suite.PROBE)
        self.assertIn("16", suite.PROBE)
        self.assertIn("never the whole value", suite.PROBE)


if __name__ == "__main__":
    unittest.main()
