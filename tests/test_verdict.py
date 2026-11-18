import base64
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
import verdict  # noqa: E402
from verdict import conclusion, decide, from_needs, parse_text, prior_verdicts, render_text, budget_base, budget_allows, stamp  # noqa: E402
import fakes  # noqa: E402

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


class MonthRecords(unittest.TestCase):
    """Fix 8: the budget base comes from the caller's Actions runs this month, not from the PRs' current commits."""

    def paid(self, today, month):
        record, _ = run(review={"findings": [], "spec": None, "cost_usd": 2.0})
        record["budget"] = {**BUDGET, "reviews_today": today, "month_usd": month}
        return record

    def test_walks_runs_newest_first_skips_gone_heads_and_stops_after_the_span(self):
        fake = fakes.GitHub(
            workflow_runs=[{"head_sha": "new", "created_at": "2026-11-18T12:00:00Z"},
                           {"head_sha": "gone", "created_at": "2026-11-18T11:00:00Z"},
                           {"head_sha": "mid", "created_at": "2026-11-18T09:00:00Z"},
                           {"head_sha": "old", "created_at": "2026-11-18T01:00:00Z"}],
            checks={"new": [fakes.check(1, self.paid(3, 30.0), "2026-11-18T12:20:00Z")],
                    "mid": [fakes.check(2, self.paid(2, 20.0), "2026-11-18T09:30:00Z")],
                    "old": [fakes.check(3, self.paid(9, 90.0), "2026-11-18T01:30:00Z")]},
            fail={"GET commits/gone/": [fakes.http_error(422)]})
        with fakes.installed(fake):
            got = fakes.github.month_records("o/r", fakes.ENV["GITHUB_WORKFLOW_REF"], Budget.NOW)
        self.assertEqual(budget_base(got, Budget.NOW), (3, 30.0))
        paths = [p for _, p, _ in fake.calls]
        self.assertIn("repos/o/r/actions/workflows/caller.yml/runs?created=%3E%3D2026-11-01&per_page=100&page=1", paths)
        self.assertFalse(any("commits/old/" in p for p in paths), "runs older than the span are not read")

    def test_an_unreadable_workflow_ref_raises(self):
        with self.assertRaises(RuntimeError):
            fakes.github.month_records("o/r", "", Budget.NOW)


class Needs(unittest.TestCase):
    def needs(self, review_result, review_flag="true"):
        tier = {"base_sha": "b", "mode": "shadow", "tiers": "T1", "has_checks": "true", "review": review_flag,
                "budget": json.dumps(BUDGET), "switch_spec": "false"}
        tier["checks"] = f"{base64.b64encode(b'unit').decode()}:{base64.b64encode(b'true').decode()}"
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


class MachineResults(Needs):
    """Fix 3: the gate knows the configured checks; a missing, empty or short result list is ERROR, never PASS."""

    def verdict_with(self, results, names=("unit",)):
        needs = self.needs({"findings": [], "spec": None, "cost_usd": 0, "error": None, "budget_refused": False})
        needs["tier"]["outputs"]["checks"] = " ".join(f"{base64.b64encode(n.encode()).decode()}:dHJ1ZQ==" for n in names)
        needs["checks"]["outputs"]["results"] = results
        inputs, _, errors = from_needs(needs, "h")
        return decide(head_sha="h", errors=errors, prior=[], **{**inputs, "mode": "shadow"})["verdict"]

    def test_dropped_results_are_an_error(self):
        self.assertEqual(self.verdict_with(""), "ERROR")
        self.assertEqual(self.verdict_with("[]"), "ERROR")

    def test_short_results_are_an_error(self):
        self.assertEqual(self.verdict_with('[{"name":"unit","result":"pass"}]', names=("unit", "lint")), "ERROR")

    def test_full_results_pass_and_a_failure_still_fails(self):
        self.assertEqual(self.verdict_with('[{"name":"unit","result":"pass"}]'), "PASS")
        self.assertEqual(self.verdict_with('[{"name":"unit","result":"fail"}]'), "FAIL")

    def test_a_dropped_tier_output_is_an_error(self):
        needs = self.needs({"findings": [], "spec": None, "cost_usd": 0, "error": None, "budget_refused": False})
        del needs["tier"]["outputs"]["has_checks"]
        _, _, errors = from_needs(needs, "h")
        self.assertIn("tier outputs missing: has_checks", errors)


class SpecItems(unittest.TestCase):
    """Fix 10: an item the engine sent with no row in the Spec table is a P0."""

    def spec(self, rows):
        return {"answer": "Yes", "items": [{"n": n, "item": i, "status": "Yes", "evidence": "x"} for n, i in rows],
                "sent": ["a", "b", "c"]}

    def test_missing_row_is_a_p0(self):
        record, result = run(review={"findings": [], "spec": self.spec([(1, "a"), (2, "b")]), "cost_usd": 1})
        self.assertEqual((record["verdict"], result), ("FAIL", "neutral"))
        self.assertEqual([f["summary"] for f in record["findings"]], ["item not judged: c"])

    def test_empty_table_judges_nothing(self):
        record, _ = run(review={"findings": [], "spec": self.spec([]), "cost_usd": 1})
        self.assertEqual([f["summary"] for f in record["findings"]], [f"item not judged: {i}" for i in "abc"])

    def test_full_table_and_no_spec_call_add_nothing(self):
        self.assertEqual(run(review={"findings": [], "spec": self.spec([(1, "a"), (2, "b"), (3, "c")]), "cost_usd": 1})[0]["verdict"], "PASS")
        self.assertEqual(run(review={"findings": [], "spec": None, "cost_usd": 1})[0]["findings"], [])


class Post(unittest.TestCase):
    """post() end to end against a fake GitHub API (fixes 1, 2, 5)."""

    def needs(self, tier=None, tier_result="success", start=None, review=None):
        tier = {"base_sha": "b", "mode": "shadow", "tiers": "T1", "has_checks": "false", "budget": json.dumps(BUDGET),
                "review": "true" if review else "false", "switch_spec": "false", **(tier or {})} if tier_result == "success" else {}
        return {"start": start or {"result": "success", "outputs": {"check_id": "7", "base_sha": "b"}},
                "tier": {"result": tier_result, "outputs": tier},
                "checks": {"result": "skipped", "outputs": {}},
                "review": {"result": "success", "outputs": {"head": "h", "result": json.dumps(review)}} if review
                else {"result": "skipped", "outputs": {}}}

    def post(self, fake, needs):
        with fakes.installed(fake, NEEDS=json.dumps(needs)):
            code, log = fakes.run(verdict.post)
        return code, log, fake.writes()

    def test_tier_crash_in_shadow_ends_neutral(self):
        code, _, writes = self.post(fakes.GitHub(), self.needs(tier_result="failure"))
        self.assertEqual([(m, p, b["conclusion"]) for m, p, b in writes], [("PATCH", "repos/o/r/check-runs/7", "neutral")])
        self.assertEqual(code, 0)
        self.assertEqual(parse_text(writes[0][2]["output"]["text"])["verdict"], "ERROR")

    def test_tier_crash_on_an_enforced_base_still_fails(self):
        code, _, writes = self.post(fakes.GitHub(config='mode = "shadow"\nenforce_branches = ["dev"]\n'),
                                    self.needs(tier_result="failure"))
        self.assertEqual((writes[0][2]["conclusion"], code), ("failure", 1))

    def test_handled_tier_error_in_shadow_is_neutral_error(self):
        code, _, writes = self.post(fakes.GitHub(), self.needs(tier={"error": "tier job: HTTPError: HTTP Error 502",
                                                                     "budget": "{}", "tiers": ""}))
        self.assertEqual((writes[0][2]["conclusion"], writes[0][2]["output"]["title"], code), ("neutral", "tier unknown error", 0))

    def test_start_fault_posts_a_new_neutral_check(self):
        code, _, writes = self.post(fakes.GitHub(), self.needs(tier_result="skipped", start={"result": "failure", "outputs": {}}))
        self.assertEqual([(m, p, b["conclusion"]) for m, p, b in writes], [("POST", "repos/o/r/check-runs", "neutral")])
        self.assertEqual(code, 0)

    def test_a_later_run_never_overwrites_an_earlier_record(self):
        first, _ = run(review={"findings": [bug("P0")], "spec": None, "cost_usd": 2.5})
        fake = fakes.GitHub(checks={"h": [fakes.check(1, first), fakes.check(7, None, status="in_progress", conclusion=None)]})
        _, _, writes = self.post(fake, self.needs(tier={"budget": json.dumps({**BUDGET, "skipped": True}),
                                                        "skip": "review skipped: budget"}))
        self.assertEqual([p for _, p, _ in writes], ["repos/o/r/check-runs/7"])
        record = parse_text(writes[0][2]["output"]["text"])
        self.assertEqual((record["verdict"], record["findings"]), ("FAIL", []))

    def test_output_over_the_limit_is_trimmed_and_still_parses(self):
        findings = [{**bug("P0"), "summary": "s" * 150, "failure": "f" * 300} for _ in range(2000)]
        _, _, writes = self.post(fakes.GitHub(), self.needs(review={"findings": findings, "spec": None, "cost_usd": 1.2345,
                                                                    "error": None, "budget_refused": False}))
        output = writes[0][2]["output"]
        self.assertLessEqual(len(output["text"]), 65535)
        self.assertLessEqual(len(output["summary"]), 65535)
        record = parse_text(output["text"])
        self.assertEqual((record["verdict"], record["cost_usd"], record.get("trimmed")), ("FAIL", 1.2345, True))

    def test_a_failed_update_still_ends_the_check(self):
        fake = fakes.GitHub(fail={"PATCH check-runs/7": [fakes.http_error(422)]})
        code, _, writes = self.post(fake, self.needs())
        self.assertEqual(len(writes), 2)
        last = writes[-1][2]
        self.assertEqual((last["status"], last["conclusion"], parse_text(last["output"]["text"])["verdict"], code),
                         ("completed", "neutral", "ERROR", 0))


class Stamp(unittest.TestCase):
    """D11 as amended."""

    def test_stamps(self):
        self.assertEqual(stamp("T0", ["checks"], ""), "checks-T0")
        self.assertEqual(stamp("T1", ["checks"], "machine only"), "none (machine only)")
        self.assertEqual(stamp("T1", ["checks"], "review skipped: budget"), "none (review skipped: budget)")
        self.assertEqual(stamp("T1", ["checks", "review"], ""), "checks,review")


if __name__ == "__main__":
    unittest.main()
