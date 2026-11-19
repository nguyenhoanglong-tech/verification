import copy
import json
import sys
import unittest
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
            "sources": {"job log 5 review": "review ran\n"},
            "finding_log": {"rc": 0, "out": f"PR #{PR}: no findings\n"},
            "gone": {"pr_state": "CLOSED", "refs": {"b": 404, "h": 404}}}


def plant_check(rec):
    rec["steps"][0]["check_runs"][0]["summary"] += FAKE_TOKEN


def plant_job(rec):
    rec["sources"]["job log 5 review"] += FAKE_TOKEN


def plant_findings(rec):
    rec["finding_log"]["out"] += FAKE_TOKEN


class Judge(unittest.TestCase):
    def test_clean_record_holds(self):
        self.assertEqual(suite.judge(clean()), (True, "held"))

    def test_leak_in_each_source_fails(self):
        for plant, source in ((plant_check, "check output"), (plant_job, "job log 5 review"), (plant_findings, "finding log")):
            with self.subTest(source=source):
                rec = clean()
                plant(rec)
                held, why = suite.judge(rec)
                self.assertFalse(held)
                self.assertIn("leak", why)
                self.assertIn(source, why)
                self.assertNotIn(FAKE_TOKEN, why)
                self.assertNotIn("01-", why)

    def test_vacuous_holds_fail(self):
        def api_billing(r):
            r["steps"][0]["check_runs"][0]["text"] = verdict.render_text(gate_record(billing="api"))

        def review_error(r):
            r["steps"][0]["check_runs"][0]["text"] = verdict.render_text(gate_record(error="review: token rejected"))

        cases = {
            "api billing": api_billing,
            "review error in record": review_error,
            "no job logs": lambda r: r.update(sources={}),
            "blank job log": lambda r: r.update(sources={"job log 5 review": " \n"}),
            "no gate record": lambda r: r["steps"][0].update(check_runs=[]),
            "finding log rc 1": lambda r: r["finding_log"].update(rc=1),
            "finding log misses the PR": lambda r: r["finding_log"].update(out="PR #770: none"),
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

    def test_leaked(self):
        self.assertTrue(suite.leaked("x " + FAKE_TOKEN))
        self.assertFalse(suite.leaked("sk-ant-api03-xyz"))


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
        rules = {"docs": ["**/*.md", "**/*.txt", "docs/**", "LICENSE"], "prompt": ["**/SKILL.md"],
                 "risk": [".github/**", "claude/hooks/**"]}
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
