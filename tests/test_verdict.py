import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
from verdict import conclusion, decide, from_needs, parse_text, prior_verdicts, render_text, budget_base, budget_allows, stamp  # noqa: E402

BUDGET = {"reviews_today": 0, "month_usd": 0.0, "reviews_per_day": 5, "budget_month_usd": 100.0, "skipped": False}


def bug(severity):
    return {"call": "bugs", "severity": severity, "file": "a.py", "line": 3, "summary": "s", "failure": "f"}


def run(mode="shadow", machine=(("unit", "pass"),), review=None, prior=(), errors=(), budget=None):
    record = decide(head_sha="h", base_sha="b", tiers="T1", mode=mode, switch_spec=bool(review and review.get("spec")),
                    machine=[{"name": n, "result": r} for n, r in machine], review=review,
                    budget=dict(budget or BUDGET), errors=list(errors), prior=list(prior))
    return record, conclusion(record)


class Verdict(unittest.TestCase):
    """D25 and D27 on recorded review outputs (#3308)."""

    def test_p1_only_passes(self):
        record, result = run(review={"findings": [bug("P1")], "spec": None, "cost_usd": 0.5})
        self.assertEqual((record["verdict"], result, record["title"]), ("PASS", "success", "T1 passed"))

    def test_spec_item_partly_would_block(self):
        spec = {"answer": "Partly", "items": [{"item": "a", "status": "Yes", "evidence": "x"},
                                              {"item": "b", "status": "Partly", "evidence": "y"}]}
        record, result = run(review={"findings": [], "spec": spec, "cost_usd": 1})
        self.assertEqual((record["verdict"], result, record["title"]), ("FAIL", "neutral", "T1 would block (shadow trial)"))
        self.assertEqual([f["call"] for f in record["findings"]], ["spec"])

    def test_bugs_p0_would_block(self):
        record, result = run(review={"findings": [bug("P0")], "spec": None, "cost_usd": 1})
        self.assertEqual((record["verdict"], result, record["title"]), ("FAIL", "neutral", "T1 would block (shadow trial)"))

    def test_failed_machine_check_blocks_when_enforced(self):
        record, result = run(mode="enforce", machine=[("unit", "fail")])
        self.assertEqual((record["verdict"], result, record["title"]), ("FAIL", "failure", "T1 blocked"))

    def test_error_enforced_is_failure_titled_rerun(self):
        record, result = run(mode="enforce", errors=["review: token exchange failed with status 401"])
        self.assertEqual((record["verdict"], result, record["title"]), ("ERROR", "failure", "T1 error: re-run"))

    def test_error_in_shadow_is_neutral_error(self):
        record, result = run(errors=["review: no result"])
        self.assertEqual((record["verdict"], result, record["title"]), ("ERROR", "neutral", "T1 error"))

    def test_failed_tier_job_fails_closed(self):
        record, result = run(mode=None, errors=["tier job failure"])
        self.assertEqual((record["verdict"], result), ("ERROR", "failure"))

    def test_budget_skip_title_and_machine_decide(self):
        record, result = run(budget={**BUDGET, "skipped": True})
        self.assertEqual((record["verdict"], result, record["title"]), ("PASS", "success", "T1 passed (review skipped: budget)"))
        record, _ = run(budget={**BUDGET, "skipped": True}, machine=[("unit", "fail")])
        self.assertEqual(record["verdict"], "FAIL")


class Sticky(unittest.TestCase):
    """G4: the sticky rule reads the verdict field, never conclusion alone."""

    def runs(self, *records, legacy_failure=False):
        out = [{"id": i + 1, "status": "completed", "conclusion": conclusion(r), "output": {"text": render_text(r)}}
               for i, r in enumerate(records)]
        if legacy_failure:
            out.append({"id": 99, "status": "completed", "conclusion": "failure", "output": {"text": None}})
        out.append({"id": 100, "status": "in_progress", "conclusion": None, "output": {"text": None}})
        return out

    def test_fail_stays_fail_after_a_passing_rerun(self):
        failed, _ = run(mode="enforce", machine=[("unit", "fail")])
        record, result = run(mode="enforce", prior=prior_verdicts(self.runs(failed), own_id=100))
        self.assertEqual((record["verdict"], result), ("FAIL", "failure"))

    def test_would_block_is_sticky_in_shadow(self):
        failed, result = run(machine=[("unit", "fail")])
        self.assertEqual(result, "neutral")
        record, result = run(prior=prior_verdicts(self.runs(failed), own_id=100))
        self.assertEqual((record["verdict"], result, record["title"]), ("FAIL", "neutral", "T1 would block (shadow trial)"))

    def test_error_is_not_sticky(self):
        errored, result = run(mode="enforce", errors=["x"])
        self.assertEqual(result, "failure")
        record, result = run(mode="enforce", prior=prior_verdicts(self.runs(errored), own_id=100))
        self.assertEqual((record["verdict"], result), ("PASS", "success"))

    def test_failure_without_a_record_counts_as_fail(self):
        self.assertEqual(prior_verdicts(self.runs(legacy_failure=True), own_id=100), ["FAIL"])

    def test_record_round_trips(self):
        record, _ = run(review={"findings": [bug("P0")], "spec": None, "cost_usd": 1.25})
        self.assertEqual(parse_text("title\n" + render_text(record)), record)
        self.assertIsNone(parse_text("no record here"))


class Budget(unittest.TestCase):
    NOW = datetime(2026, 11, 18, 15, 0, tzinfo=timezone.utc)

    def rec(self, today, month):
        return {"budget": {"reviews_today": today, "month_usd": month}}

    def test_newest_record_carries_the_totals(self):
        records = [("2026-11-18T10:00:00Z", self.rec(2, 30.0)), ("2026-11-18T12:00:00Z", self.rec(3, 33.5))]
        self.assertEqual(budget_base(records, self.NOW), (3, 33.5))

    def test_a_record_without_totals_does_not_reset_them(self):
        records = [("2026-11-18T10:00:00Z", self.rec(2, 30.0)), ("2026-11-18T12:00:00Z", {"budget": {}})]
        self.assertEqual(budget_base(records, self.NOW), (2, 30.0))

    def test_day_and_month_reset(self):
        self.assertEqual(budget_base([("2026-11-17T23:00:00Z", self.rec(5, 40.0))], self.NOW), (0, 40.0))
        self.assertEqual(budget_base([("2026-10-31T23:00:00Z", self.rec(5, 99.0))], self.NOW), (0, 0.0))

    def test_caps(self):
        self.assertFalse(budget_allows(0, 0, 0, 100))      # reviews_per_day = 0 turns paid reviews off
        self.assertFalse(budget_allows(5, 0, 5, 100))
        self.assertFalse(budget_allows(0, 100.0, 5, 100))  # the month already sums to budget_month_usd
        self.assertTrue(budget_allows(4, 99.9, 5, 100))


class RecentRecords(unittest.TestCase):
    def test_a_record_on_an_earlier_commit_of_a_pr_counts(self):
        import github
        paid, _ = run(review={"findings": [], "spec": None, "cost_usd": 2.0})
        paid["budget"] = {**BUDGET, "reviews_today": 1, "month_usd": 2.0}
        commit = lambda text: {"commit": {"checkSuites": {"nodes": [{"checkRuns": {"nodes": [
            {"completedAt": "2026-11-18T10:00:00Z", "text": text}]}}]}}}
        data = {"repository": {"pullRequests": {"nodes": [{"commits": {"nodes": [commit(render_text(paid)), commit(None)]}}]}}}
        real = github.graphql
        github.graphql = lambda query, **v: data
        try:
            got = github.recent_records("o/r")
        finally:
            github.graphql = real
        self.assertEqual(budget_base(got, Budget.NOW), (1, 2.0))


class Needs(unittest.TestCase):
    def needs(self, review_result, review_flag="true"):
        tier = {"base_sha": "b", "mode": "shadow", "tiers": "T1", "has_checks": "true", "review": review_flag,
                "budget": json.dumps(BUDGET), "switch_spec": "false"}
        return {"start": {"result": "success", "outputs": {"check_id": "100"}},
                "tier": {"result": "success", "outputs": tier},
                "checks": {"result": "success", "outputs": {"head": "h", "results": '[{"name":"unit","result":"pass"}]'}},
                "review": {"result": "success", "outputs": {"head": "h", "result": json.dumps(review_result)}}}

    def test_spend_limit_refusal_is_a_budget_skip_not_an_error(self):
        inputs, ran, errors = from_needs(self.needs({"findings": [], "spec": None, "cost_usd": 0, "error": None,
                                                     "budget_refused": True}), "h")
        record = decide(head_sha="h", errors=errors, prior=[], **inputs)
        self.assertEqual((record["verdict"], record["budget"]["skipped"], errors), ("PASS", True, []))

    def test_credit_error_is_an_error(self):
        inputs, _, errors = from_needs(self.needs({"findings": [], "spec": None, "cost_usd": 0, "budget_refused": False,
                                                   "error": "bugs call: Credit balance is too low"}), "h")
        self.assertEqual(decide(head_sha="h", errors=errors, prior=[], **inputs)["verdict"], "ERROR")

    def test_review_on_another_head_is_an_error(self):
        needs = self.needs({"findings": [], "spec": None, "cost_usd": 0, "error": None, "budget_refused": False})
        needs["review"]["outputs"]["head"] = "other"
        _, _, errors = from_needs(needs, "h")
        self.assertIn("review ran on another head", errors)


class Stamp(unittest.TestCase):
    """D11 as amended."""

    def test_stamps(self):
        self.assertEqual(stamp("T0", ["checks"], ""), "checks-T0")
        self.assertEqual(stamp("T1", ["checks"], "machine only"), "none (machine only)")
        self.assertEqual(stamp("T1", ["checks"], "review skipped: budget"), "none (review skipped: budget)")
        self.assertEqual(stamp("T1", ["checks", "review"], ""), "checks,review")


if __name__ == "__main__":
    unittest.main()
