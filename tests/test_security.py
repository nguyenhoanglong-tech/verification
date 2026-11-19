"""dotfiles#3408 add-on: a PR that touches a [tiers] risk path also gets a security pass, in the same sandbox, on the
same billing route and with the same finding schema as the Bugs call. Its P0 fails the gate, its error is an ERROR."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "engine/claude-job"))
import fakes  # noqa: E402
import review  # noqa: E402
import tier  # noqa: E402
import verdict  # noqa: E402

SEC_P0 = {"severity": "P0", "file": ".github/workflows/x.yml", "line": 7, "summary": "echoes a secret into the log",
          "failure_scenario": "anyone with read access reads the token from the run log"}
BUDGET = {"reviews_today": 0, "month_usd": 0.0, "reviews_per_day": 5, "budget_month_usd": 100.0,
          "subscription_fallback": False, "subscription_per_day": 0, "skipped": False, "route": "api"}


def f(name, lines=10):
    return {"filename": name, "additions": lines, "deletions": 0}


def tier_outputs(files):
    with tempfile.NamedTemporaryFile("r", suffix=".out") as out, \
            fakes.installed(fakes.GitHub(files=files), GITHUB_OUTPUT=out.name):
        fakes.run(tier.github_main)
        return dict(line.split("=", 1) for line in Path(out.name).read_text().splitlines() if "=" in line)


def reply(text, cost):
    return 0, json.dumps({"is_error": False, "subtype": "success", "result": text, "total_cost_usd": cost}), ""


def review_main(security, sec_reply=None):
    """(the review job's result, the calls it made by name). The Bugs call finds nothing; the security call, when the
    engine makes one, answers with sec_reply."""
    calls = []

    def claude(args, prompt, billing, runner):
        name = "bugs" if prompt.startswith("/code-review") else "spec" if "Done-when" in prompt else "security"
        calls.append(name)
        if name == "security":
            return sec_reply or reply(f"```json\n{json.dumps([SEC_P0])}\n```", 0.3)
        return reply("```json\n[]\n```", 0.5)
    with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
            "RUNNER_TEMP": tmp, "HEAD_DIR": tmp, "BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m", "EFFORT": "medium",
            "SPEC_TEXT": '""', "PACE": json.dumps(BUDGET), "SECURITY": security}), \
            mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
            mock.patch.object(review, "claude", claude):
        out, _ = fakes.run(review.main)
    return out, calls


def judge(review_result, security="true"):
    """The record the gate job writes for a T2 risk-path run whose review job returned review_result."""
    tier_out = {"base_sha": "b", "mode": "shadow", "tiers": "T2", "has_checks": "false", "review": "true",
                "security": security, "budget": json.dumps(BUDGET), "switch_spec": "false", "reasons": "r"}
    needs = {"start": {"result": "success", "outputs": {"base_sha": "b"}},
             "tier": {"result": "success", "outputs": tier_out},
             "checks": {"result": "skipped", "outputs": {}},
             "review": {"result": "success", "outputs": {"head": "h", "result": json.dumps(review_result)}}}
    when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with fakes.installed(fakes.GitHub()), mock.patch.object(fakes.github, "month_records",
                                                            lambda *a: [(when, {"budget": BUDGET})]):
        (record, _), _ = fakes.run(verdict.judge, fakes.github, needs, "o/r", "h", "url", "dev")
    return record


class Security(unittest.TestCase):
    def test_the_pass_runs_exactly_when_a_risk_path_is_touched(self):
        cases = {"risk path": ([f(".github/workflows/x.yml")], "T2", "true"),
                 "T2 by size alone": ([f("a.py", 400)], "T2", "false"),
                 "T1": ([f("a.py")], "T1", "false")}
        for name, (files, tiers, owed) in cases.items():
            out = tier_outputs(files)
            self.assertEqual((out.get("tiers"), out.get("review"), out.get("security")), (tiers, "true", owed), name)
        self.assertEqual(review_main("true")[1], ["bugs", "security"])
        self.assertEqual(review_main("false")[1], ["bugs"])

    def test_a_security_p0_fails_the_verdict(self):
        out, _ = review_main("true")
        record = judge(out)
        self.assertEqual(out.get("findings"), [], "the Bugs call found nothing")
        self.assertEqual((record["verdict"], record["title"]), ("FAIL", "T2 would block (shadow trial)"))

    def test_a_security_error_makes_the_verdict_error_never_pass(self):
        prose = reply("PROSE-ONLY: looks safe to me.", 0.2)
        out, _ = review_main("true", sec_reply=prose)
        self.assertTrue((out.get("error") or "").startswith("security call: unparseable output"), out.get("error"))
        self.assertEqual(judge(out)["verdict"], "ERROR")
        failed = (1, "", "boom")
        self.assertEqual(judge(review_main("true", sec_reply=failed)[0])["verdict"], "ERROR")
        clean_without_pass = {"findings": [], "spec": None, "cost_usd": 0.5, "billing": "api", "error": None,
                              "budget_refused": False}
        self.assertEqual(judge(clean_without_pass)["verdict"], "ERROR", "an owed pass missing from the result")

    def test_its_cost_and_findings_land_in_the_record_under_their_own_key(self):
        record = judge(review_main("true")[0])
        security = record.get("security") or {}
        self.assertEqual((security.get("ran"), security.get("cost_usd")), (True, 0.3))
        self.assertEqual([(x["call"], x["severity"], x["file"]) for x in security.get("findings", [])],
                         [("security", "P0", ".github/workflows/x.yml")])
        self.assertEqual(record["findings"], [], "Bugs findings stay under their own key")
        self.assertAlmostEqual(record["cost_usd"], 0.8, msg="the run's API cost, which month_usd adds, covers both calls")
        self.assertIsNone(judge(review_main("false")[0], security="false").get("security"), "not owed: no pass")


if __name__ == "__main__":
    unittest.main()
