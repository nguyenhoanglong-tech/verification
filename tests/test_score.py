import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine/claude-job"))
from score import last_json, score  # noqa: E402

OWED = ["sandbox/calc.py"]


def result(structured=None, is_error=False, text="", cost=0.12):
    r = {"type": "result", "subtype": "success", "is_error": is_error, "result": text, "total_cost_usd": cost}
    if structured is not None:
        r["structured_output"] = structured
    return r


def finding(severity):
    return {"file": "sandbox/calc.py", "line": 3, "severity": severity, "summary": "x"}


class Score(unittest.TestCase):
    def verdict(self, *args, **kw):
        return score("review", *args, **kw)[0]

    def test_clean_review_passes(self):
        self.assertEqual(self.verdict(result({"files_reviewed": OWED, "findings": [finding("minor")]}), OWED), "PASS")

    def test_blocking_finding_fails(self):
        v, cost, summary, md = score("review", result({"files_reviewed": OWED, "findings": [finding("blocking")]}), OWED)
        self.assertEqual(v, "FAIL")
        self.assertIn("review: 1 blocking", summary)
        self.assertEqual(cost, 0.12)

    def test_credit_error_is_error(self):
        v, _, summary, _ = score("review", result(is_error=True, text="Credit balance is too low", cost=0), OWED)
        self.assertEqual(v, "ERROR")
        self.assertIn("Credit balance is too low", summary)

    def test_auth_error_is_error(self):
        self.assertEqual(self.verdict(result(is_error=True, text="API Error: 401 authentication_error"), OWED), "ERROR")

    def test_is_error_with_structured_output_is_error(self):
        self.assertEqual(self.verdict(result({"files_reviewed": OWED, "findings": []}, is_error=True), OWED), "ERROR")

    def test_no_cli_output_is_error(self):
        self.assertEqual(self.verdict(None, OWED, stderr="claude: command not found"), "ERROR")

    def test_exchange_failure_is_error(self):
        v, _, summary, _ = score("review", None, OWED, exchange_error="Token exchange failed with status 401")
        self.assertEqual(v, "ERROR")
        self.assertIn("token exchange failed", summary)

    def test_malformed_structured_output_is_error(self):
        self.assertEqual(self.verdict(result({"findings": "none"}), OWED), "ERROR")

    def test_owed_file_not_read_is_error(self):
        self.assertEqual(self.verdict(result({"files_reviewed": [], "findings": []}), OWED), "ERROR")

    def test_nothing_owed_is_error(self):
        self.assertEqual(self.verdict(result({"files_reviewed": [], "findings": []}), []), "ERROR")

    def test_last_json_skips_warning_lines(self):
        self.assertEqual(last_json('Warning: x\n{"type": "result"}\n'), {"type": "result"})
        self.assertIsNone(last_json(""))


if __name__ == "__main__":
    unittest.main()
