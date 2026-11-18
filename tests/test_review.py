import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine/claude-job"))
import review  # noqa: E402
from review import bugs_findings, failure_kind, outcome, spec_table  # noqa: E402
sys.path.insert(0, str(ROOT / "tests"))
import fakes  # noqa: E402

HEAD = "/tmp/review/data/head"


class Failures(unittest.TestCase):
    def test_org_spend_limit_is_budget(self):
        text = ('API Error: 400 {"type":"error","error":{"type":"invalid_request_error","message":"You have reached your '
                'specified API usage limits. You will regain access on 2026-12-01 at 00:00 UTC."}}')
        self.assertEqual(failure_kind(text), "budget")
        self.assertEqual(failure_kind("You have reached your specified workspace API usage limits."), "budget")

    def test_credit_and_other_failures_stay_errors(self):
        self.assertEqual(failure_kind("Credit balance is too low"), "credit")
        self.assertEqual(failure_kind('429 {"error":{"type":"rate_limit_error","message":"enforced_spend_limit_reached"}}'), "error")
        self.assertEqual(failure_kind("no result from the CLI"), "error")

    def test_outcome(self):
        self.assertEqual(outcome(1, "", "boom")[1][:22], "no result from the CLI")
        result, failure = outcome(0, json.dumps({"is_error": True, "subtype": "success", "result": "API Error: 400"}), "")
        self.assertIn("API Error: 400", failure)
        self.assertEqual(outcome(0, json.dumps({"is_error": False, "result": "[]"}), "")[1], "")
        forked = {"is_error": False, "subtype": "success", "result": "API Error: 400 You have reached your specified API "
                  "usage limits. You will regain access on 2026-12-01 at 00:00 UTC."}
        self.assertEqual(failure_kind(outcome(0, json.dumps(forked), "")[1]), "budget")
        credit = {"is_error": False, "subtype": "success", "result": "Credit balance is too low"}
        self.assertEqual(failure_kind(outcome(0, json.dumps(credit), "")[1]), "credit")


class RefusalOnlyFromTheCli(unittest.TestCase):
    """Fix 6: the spend-limit and credit sentences count only when the CLI wrote them, never in model output."""
    SENTENCE = "API Error: 400 You have reached your specified API usage limits. You will regain access on 2026-12-01."

    def test_structured_output_is_never_a_refusal(self):
        result = {"is_error": False, "result": self.SENTENCE, "structured_output": {"findings": []}, "total_cost_usd": 0.4}
        self.assertEqual(outcome(0, json.dumps(result), "")[1], "")

    def test_model_prose_that_quotes_the_sentence_is_output(self):
        result = {"is_error": False, "result": self.SENTENCE, "total_cost_usd": 0.00064}
        self.assertEqual(outcome(0, json.dumps(result), "")[1], "")
        result = {"is_error": False, "result": "Credit balance is too low", "total_cost_usd": 0.2}
        self.assertEqual(outcome(0, json.dumps(result), "")[1], "")

    def test_cli_refusals_still_count(self):
        forked = {"is_error": False, "subtype": "success", "result": self.SENTENCE, "total_cost_usd": 0}
        self.assertEqual(failure_kind(outcome(0, json.dumps(forked), "")[1]), "budget")
        flagged = {"is_error": True, "subtype": "success", "result": self.SENTENCE, "total_cost_usd": 0.5}
        self.assertEqual(failure_kind(outcome(1, json.dumps(flagged), "")[1]), "budget")


class Logging(unittest.TestCase):
    """Fix 4: nothing from the issue, the head or the model reaches the command parser."""

    def test_prompt_is_printed_only_inside_stop_commands(self):
        done = SimpleNamespace(returncode=0, stdout="{}", stderr="")
        with mock.patch.object(review.subprocess, "run", return_value=done), tempfile.TemporaryDirectory() as d:
            _, log = fakes.run(review.claude, ["--model", "m"], "check ISSUE-TEXT\n::add-mask::x\nISSUE-TEXT again",
                               Path(d) / "token", Path(d))
        self.assertEqual(fakes.outside_stop_commands(log, "ISSUE-TEXT"), [])
        self.assertIn("ISSUE-TEXT", log)


class SpecBudget(unittest.TestCase):
    """Fix 7: the budget is read again right before the Spec call."""

    def test_spec_call_skipped_when_the_pace_is_reached_after_the_bugs_call(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        records = [(now, {"budget": {"reviews_today": 5, "month_usd": 10.0}})]
        bugs = json.dumps({"is_error": False, "result": "[]", "structured_output": {"findings": []}, "total_cost_usd": 1.5})
        calls = []

        def claude(args, prompt, token_file, home):
            calls.append(prompt)
            return 0, bugs, ""
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "RUNNER_TEMP": tmp, "HEAD_DIR": tmp, "BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m", "EFFORT": "medium",
                "SPEC_TEXT": json.dumps("## Done when\n- a\n"), "GITHUB_REPOSITORY": "o/r",
                "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/c.yml@refs/heads/main",
                "PACE": json.dumps({"reviews_per_day": 5, "budget_month_usd": 100})}), \
                mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
                mock.patch.object(review, "claude", claude), \
                mock.patch.object(fakes.github, "month_records", lambda *a: records, create=True):
            out, _ = fakes.run(review.main)
        self.assertEqual(len(calls), 1, "the Spec call did not run")
        self.assertTrue(out.get("spec_skipped"))
        self.assertEqual((out["cost_usd"], out["spec"], out["error"]), (1.5, None, None))


class Prepare(unittest.TestCase):
    """Fix 11: a head file that is not UTF-8 does not crash the review."""

    def test_non_utf8_diff(self):
        with tempfile.TemporaryDirectory() as d:
            head, data = Path(d) / "head", Path(d) / "data"
            head.mkdir()
            data.mkdir()
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.hooksPath=/dev/null",
                   "-c", "commit.gpgsign=false", "-C", str(head)]
            subprocess.run(git + ["init", "-q"], check=True)
            (head / "a.txt").write_text("a\n")
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["commit", "-qm", "base"], check=True)
            base = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            (head / "latin1.txt").write_bytes(b"caf\xe9\n")
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["commit", "-qm", "head"], check=True)
            fakes.run(review.prepare, head, base, data)
            self.assertIn("caf\ufffd", (data / "diff.patch").read_text())


class Bugs(unittest.TestCase):
    def test_json_array_from_code_review_text(self):
        text = ('Findings:\n```json\n[{"file": "' + HEAD + '/a.py", "line": 4, "summary": "off by one", '
                '"failure_scenario": "age 18 -> False", "severity": "P0"},\n {"file": "b.py", "summary": "style"}]\n```')
        got = bugs_findings({"result": text}, HEAD)
        self.assertEqual([(f["file"], f["line"], f["severity"]) for f in got], [("a.py", 4, "P0"), ("b.py", None, "P0")])
        self.assertEqual(got[0]["failure"], "age 18 -> False")

    def test_structured_output_wins(self):
        out = {"findings": [{"severity": "P1", "file": "a.py", "line": 1, "summary": "s", "failure_scenario": "f"}]}
        self.assertEqual(bugs_findings({"structured_output": out, "result": "[]"}, HEAD)[0]["severity"], "P1")

    def test_empty_and_unparseable(self):
        self.assertEqual(bugs_findings({"result": "No findings.\n[]"}, HEAD), [])
        with self.assertRaises(ValueError):
            bugs_findings({"result": "I could not review this."}, HEAD)


class Spec(unittest.TestCase):
    def test_table(self):
        out = {"answer": "Partly", "items": [{"item": "a", "status": "Yes", "evidence": "x:1"},
                                             {"item": "b", "status": "No", "evidence": "missing"}]}
        self.assertEqual(spec_table({"structured_output": out})["items"][1]["status"], "No")
        numbered = {"answer": "Yes", "items": [{"n": 2, "item": "b", "status": "Yes", "evidence": "x:1"}]}
        self.assertEqual(spec_table({"structured_output": numbered})["items"][0]["n"], 2)
        with self.assertRaises(ValueError):
            spec_table({"structured_output": {"answer": "Maybe", "items": []}})


if __name__ == "__main__":
    unittest.main()
