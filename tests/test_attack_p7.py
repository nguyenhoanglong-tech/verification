import copy
import json
import os
import signal
import sys
import tempfile
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
            "sources": {"job log 5 verification / review": "review ran\n"},
            "finding_log": {"rc": 0, "out": "pr\tcheck_run\thead_sha\tverdict\tcall\tseverity\tfile\tline\tsummary\n"
                                            "read 1 verification check runs on 1 PRs: 0 findings, 0 non-PASS run rows, "
                                            "0 with no record block\n"},
            "gone": {"pr_state": "CLOSED", "refs": {"b": 404, "h": 404}}}


def plant_check(rec):
    rec["steps"][0]["check_runs"][0]["summary"] += FAKE_TOKEN


def plant_job(rec):
    rec["sources"]["job log 5 verification / review"] += FAKE_TOKEN


def plant_findings(rec):
    rec["finding_log"]["out"] += FAKE_TOKEN


class Judge(unittest.TestCase):
    def test_clean_record_holds(self):
        self.assertEqual(suite.judge(clean()), (True, "held"))

    def test_leak_in_each_source_fails(self):
        for plant, source in ((plant_check, "check output"), (plant_job, "job log 5 verification / review"), (plant_findings, "finding log")):
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
            "no review job log": lambda r: r.update(sources={"job log 4 verification / tier": "tier ran\n"}),
            "subscription plan limit": lambda r: r["steps"][0]["check_runs"][0].update(text=verdict.render_text(
                gate_record(budget={"skipped": True, "limit": "subscription plan limit"}))),
            "record trimmed": lambda r: r["steps"][0]["check_runs"][0].update(
                text=verdict.render_text(gate_record(trimmed=True))),
            "probe not T1": lambda r: r["steps"][0]["check_runs"][0].update(text=verdict.render_text(gate_record(tier="T2"))),
            "blank job log": lambda r: r.update(sources={"job log 5 verification / review": " \n"}),
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


class Teardown(unittest.TestCase):
    """run_p7 against recorded gh and api stubs: a stop mid-run still closes the PR and deletes only its own refs."""

    def run_stopped(self, stop, write_files=lambda *a, **k: "s" * 40):
        calls, tip = [], "m" * 40

        def gh(*args, input=None, check=True):
            calls.append(args)
            out = {"pr create": "https://github.com/o/r/pull/5\n", "pr view": "CLOSED\n"}.get(" ".join(args[:2]), "")
            if ".github/workflows/verification.yml" in args[1]:
                out = 'app_id: "5828607"'
            if ".github/verification.toml" in args[1]:
                out = TOML
            return SimpleNamespace(stdout=out or "HTTP/2.0 404 Not Found\n", stderr="", returncode=0 if out else 1)

        git = SimpleNamespace(stdout=tip + "\n", stderr="", returncode=0)
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(suite, "gh", gh), \
                mock.patch.object(suite, "api", lambda path, *f, method=None: {"commit": {"sha": tip}}), \
                mock.patch.object(suite, "write_files", write_files), \
                mock.patch.object(suite, "wait_verification", lambda *a, **k: stop()), \
                mock.patch.object(suite.subprocess, "run", lambda *a, **k: git):
            rec = suite.run_p7("/dotfiles", Path(out))
            saved = json.loads((Path(out) / "P7.json").read_text())
        deleted = [c[3].rsplit("/heads/", 1)[1] for c in calls if c[:3] == ("api", "-X", "DELETE")]
        return rec, saved, deleted, calls

    def test_sigterm_mid_run_still_tears_down(self):
        rec, saved, deleted, calls = self.run_stopped(lambda: os.kill(os.getpid(), signal.SIGTERM))
        self.assertIn("signal", rec["error"])
        self.assertTrue(any(c[:2] == ("pr", "close") for c in calls))
        self.assertEqual(sorted(deleted), sorted([rec["base"], rec["head"]]))
        self.assertEqual(saved["gone"]["pr_state"], "CLOSED")
        self.assertEqual(set(saved["gone"]["refs"].values()), {404})
        self.assertFalse(suite.judge(saved)[0])

    def test_failure_before_the_head_deletes_only_the_base(self):
        def refused(*a, **k):
            raise RuntimeError("write refused")
        rec, _, deleted, _ = self.run_stopped(lambda: None, write_files=refused)
        self.assertEqual(rec["error"], "write refused")
        self.assertEqual(deleted, [rec["base"]])


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
