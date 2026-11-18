import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine/claude-job"))
from review import bugs_findings, failure_kind, outcome, spec_table  # noqa: E402

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
        with self.assertRaises(ValueError):
            spec_table({"structured_output": {"answer": "Maybe", "items": []}})


if __name__ == "__main__":
    unittest.main()
