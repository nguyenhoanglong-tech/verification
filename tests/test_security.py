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
        assert not verdict.parse_review(json.dumps(out))[1], verdict.parse_review(json.dumps(out))[1]
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


class Edges(unittest.TestCase):
    def test_a_spend_refusal_on_the_security_call_is_a_budget_skip_that_says_the_pass_did_not_run(self):
        refused = reply("API Error: 400 You have reached your specified API usage limits.", 0)
        with mock.patch.object(review, "reroute", return_value=(None, "API spend limit refused the call")):
            out, calls = review_main("true", sec_reply=refused)
        self.assertEqual((calls, out["budget_refused"], out["security"]["ran"]), (["bugs", "security"], True, False))
        record = judge(out)
        self.assertEqual((record["verdict"], record["budget"]["skipped"], record["security"]["ran"]), ("PASS", True, False))
        self.assertTrue(record["title"].endswith("(review skipped: budget)"), record["title"])

    def test_a_risk_path_review_skipped_for_budget_says_the_pass_was_owed(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        spent = {"schema": 1, "verdict": "PASS", "budget": {"reviews_today": 5, "month_usd": 1.0}}
        fake = fakes.GitHub(files=[f(".github/workflows/x.yml")], workflow_runs=[{"head_sha": "old", "created_at": now}],
                            checks={"old": [fakes.check(1, spent, now)]})
        with tempfile.NamedTemporaryFile("r", suffix=".out") as o, fakes.installed(fake, GITHUB_OUTPUT=o.name):
            fakes.run(tier.github_main)
            out = dict(line.split("=", 1) for line in Path(o.name).read_text().splitlines() if "=" in line)
        self.assertEqual((out["review"], out["security"], out["skip"]), ("false", "true", "review skipped: budget"))
        needs = {"start": {"result": "success", "outputs": {"base_sha": "b"}},
                 "tier": {"result": "success", "outputs": out},
                 "checks": {"result": "skipped", "outputs": {}}, "review": {"result": "skipped", "outputs": {}}}
        inputs, _, errors = verdict.from_needs(needs, "h")
        record = verdict.decide(head_sha="h", errors=errors, prior=[], **inputs)
        self.assertEqual((record["verdict"], record["budget"]["skipped"], record["security"]["ran"], errors),
                         ("PASS", True, False, []))

    def test_a_long_security_report_is_trimmed_and_still_fails(self):
        out, _ = review_main("true")
        out["security"]["findings"] = [{**out["security"]["findings"][0], "summary": "x" * 3000}] * 60
        record = judge(out)
        self.assertEqual(record["verdict"], "FAIL")
        self.assertTrue(record.get("trimmed"))
        self.assertLessEqual(len(verdict.render_text(record)), verdict.LIMIT)
        self.assertEqual(verdict.parse_text(verdict.render_text(record))["security"]["ran"], True)

    def test_the_workflow_passes_the_decision_from_the_tier_job_to_the_review_step(self):
        gate = (ROOT / ".github/workflows/gate.yml").read_text()
        action = (ROOT / "engine/claude-job/action.yml").read_text()
        self.assertIn("security: ${{ steps.t.outputs.security }}", gate)
        self.assertIn("security: ${{ needs.tier.outputs.security }}", gate)
        self.assertIn("SECURITY: ${{ inputs.security }}", action)


def gate_needs(result_text, security="true", mode="enforce", **tier_extra):
    """The gate job's NEEDS for a T2 run whose review job succeeded on this head and returned result_text."""
    tier_out = {"base_sha": "b", "mode": mode, "tiers": "T2", "has_checks": "false", "review": "true",
                "security": security, "budget": json.dumps(BUDGET), "switch_spec": "false", "reasons": "r", **tier_extra}
    return {"start": {"result": "success", "outputs": {"base_sha": "b"}},
            "tier": {"result": "success", "outputs": tier_out},
            "checks": {"result": "skipped", "outputs": {}},
            "review": {"result": "success", "outputs": {"head": "h", "result": result_text}}}


def verdict_of(needs):
    inputs, _, errors = verdict.from_needs(needs, "h")
    return verdict.decide(head_sha="h", errors=errors, prior=[], **inputs), errors


class FailClosed(unittest.TestCase):
    """Codex review of 9987fc0, P0s: an empty review result and an unreadable budget are ERRORs, never PASS."""

    def test_an_empty_or_null_review_result_is_an_error_never_a_pass(self):
        clean = {"findings": [], "spec": None, "cost_usd": 0.5, "billing": "api", "error": None, "budget_refused": False}
        cases = {"{} with the pass owed": ("{}", "true"), "null with the pass owed": ("null", "true"),
                 "an empty security entry": (json.dumps({**clean, "security": {}}), "true"),
                 "a null security entry": (json.dumps({**clean, "security": None}), "true"),
                 "{} with no pass owed": ("{}", "false"), "null with no pass owed": ("null", "false"),
                 "no findings list": (json.dumps({**clean, "findings": None}), "false")}
        for name, (text, owed) in cases.items():
            with self.subTest(name):
                record, errors = verdict_of(gate_needs(text, security=owed))
                self.assertEqual((record["verdict"], verdict.conclusion(record)), ("ERROR", "failure"), errors)

    def test_an_unreadable_budget_is_an_error_not_a_budget_skip(self):
        fake = fakes.GitHub(config='mode = "enforce"\n', files=[f(".github/workflows/x.yml")],
                            fail={"GET actions/workflows": [fakes.http_error(403)]})
        with tempfile.NamedTemporaryFile("r", suffix=".out") as o, fakes.installed(fake, GITHUB_OUTPUT=o.name):
            fakes.run(tier.github_main)
            out = dict(line.split("=", 1) for line in Path(o.name).read_text().splitlines() if "=" in line)
        self.assertEqual((out["review"], out["security"]), ("false", "true"))
        needs = {"start": {"result": "success", "outputs": {"base_sha": "b"}},
                 "tier": {"result": "success", "outputs": out},
                 "checks": {"result": "skipped", "outputs": {}}, "review": {"result": "skipped", "outputs": {}}}
        record, errors = verdict_of(needs)
        self.assertEqual((record["verdict"], verdict.conclusion(record), record["title"]),
                         ("ERROR", "failure", "T2 error: re-run"), errors)
        self.assertIn("budget read failed", out.get("error", ""))


class Record(unittest.TestCase):
    """Codex review of 9987fc0, P1s."""

    def post(self, needs, fail=None, prior_month=1.0):
        fake = fakes.GitHub(fail=fail or {})
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with fakes.installed(fake, NEEDS=json.dumps(needs)), mock.patch.object(
                fakes.github, "month_records", lambda *a: [(when, {"budget": {**BUDGET, "month_usd": prior_month}})]):
            fakes.run(verdict.post)
        return [verdict.parse_text(b["output"]["text"]) for _, _, b in fake.writes()]

    def test_a_failed_publish_keeps_the_completed_security_result(self):
        needs = gate_needs(json.dumps(review_main("true")[0]))
        records = self.post(needs, fail={"POST check-runs": [fakes.http_error(422)]})
        self.assertEqual(len(records), 2)
        security = records[-1]["security"] or {}
        self.assertEqual((security.get("ran"), [x["severity"] for x in security.get("findings", [])]), (True, ["P0"]))
        self.assertEqual(records[-1]["verdict"], "FAIL", "the fallback is never weaker than what the judge found")

    def test_a_failed_publish_of_a_long_report_still_fits(self):
        result = review_main("true")[0]
        result["security"]["findings"] = [{**result["security"]["findings"][0], "summary": "x" * 3000}] * 60
        records = self.post(gate_needs(json.dumps(result)), fail={"POST check-runs": [fakes.http_error(422)]})
        self.assertEqual((len(records), records[-1]["verdict"]), (2, "FAIL"))
        self.assertLessEqual(len(verdict.render_text(records[-1])), verdict.LIMIT)

    def test_a_security_entry_without_its_cost_is_an_error_not_a_crash(self):
        clean = {"findings": [], "spec": None, "cost_usd": 0.5, "billing": "api", "error": None, "budget_refused": False}
        record, errors = verdict_of(gate_needs(json.dumps({**clean, "security": {"ran": True, "findings": []}})))
        self.assertEqual(record["verdict"], "ERROR", errors)

    def test_the_posted_month_total_counts_the_security_spend(self):
        record = self.post(gate_needs(json.dumps(review_main("true")[0])))[-1]
        self.assertEqual((record["security"]["cost_usd"], record["cost_usd"]), (0.3, 0.8))
        self.assertAlmostEqual(record["budget"]["month_usd"], 1.8)

    def test_a_record_with_no_pass_owed_says_so_with_an_explicit_null(self):
        record = self.post(gate_needs(json.dumps(review_main("false")[0]), security="false"))[-1]
        self.assertIn("security", record)
        self.assertIsNone(record["security"])

    def test_a_dropped_security_tier_output_is_an_error(self):
        needs = gate_needs(json.dumps(review_main("true")[0]))
        del needs["tier"]["outputs"]["security"]
        record, errors = verdict_of(needs)
        self.assertIn("tier outputs missing: security", errors)
        self.assertNotEqual(record["verdict"], "PASS")

    def test_the_pass_is_owed_on_a_truncated_list_and_on_a_rename_out_of_a_risk_path(self):
        self.assertTrue(tier.classify([f("a.py")], {}, truncated=True).security)
        renamed = {"filename": "ci/x.yml", "previous_filename": ".github/workflows/x.yml", "additions": 1, "deletions": 1}
        self.assertTrue(tier.classify([renamed], {}).security)
        self.assertFalse(tier.classify([f("a.py", 400)], {}).security)

    def test_the_prompt_asks_for_a_finding_on_a_workflow_with_no_permissions_block(self):
        text = (ROOT / "engine/prompts/security.md").read_text()
        self.assertIn("no `permissions:` block", text)
        self.assertIn("echo", text)

    def test_a_standards_path_outside_the_base_checkout_is_refused(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            (Path(tmp) / "outside.md").write_text("x\n")
            old = os.getcwd()
            os.chdir(base)
            try:
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp, "HEAD_DIR": tmp, "BASE_SHA": "b", "ANTHROPIC": "{}",
                                                  "MODEL": "m", "EFFORT": "medium", "SPEC_TEXT": '""', "SECURITY": "true",
                                                  "STANDARDS": "../outside.md", "PACE": json.dumps(BUDGET)}), \
                        mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
                        mock.patch.object(review, "claude", lambda *a: calls.append(a) or reply("```json\n[]\n```", 0.1)):
                    out, _ = fakes.run(review.main)
                    assert not verdict.parse_review(json.dumps(out))[1], verdict.parse_review(json.dumps(out))[1]
            finally:
                os.chdir(old)
        self.assertEqual(calls, [], "no model call reads a file outside the base")
        self.assertIn("outside the base checkout", out.get("error") or "")


class FailClosedByConstruction(unittest.TestCase):
    """#77 round 3 (checklist C1-C4): PASS only from a positive, fully validated set; everything else is ERROR."""

    def judge_needs(self, needs, month_records=None):
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        records = month_records or (lambda *a: [(when, {"budget": BUDGET})])
        with fakes.installed(fakes.GitHub()), mock.patch.object(fakes.github, "month_records", records):
            (record, _), _ = fakes.run(verdict.judge, fakes.github, needs, "o/r", "h", "url", "dev")
        return record

    def test_c1_a_string_false_refusal_flag_is_an_error(self):
        result = fakes.review_result(budget_refused="false", security=None)
        record = self.judge_needs(gate_needs(json.dumps(result), security="true"))
        self.assertEqual((record["verdict"], verdict.conclusion(record)), ("ERROR", "failure"), record["error"])

    def test_c1_a_bool_security_cost_is_an_error(self):
        security = {"ran": True, "findings": [], "cost_usd": True, "subscription_cost_usd": False}
        result = fakes.review_result(security=security, calls=["bugs", "security"])
        record = self.judge_needs(gate_needs(json.dumps(result), security="true"))
        self.assertEqual((record["verdict"], verdict.conclusion(record)), ("ERROR", "failure"), record["error"])

    def test_c1_c2_an_owed_spec_call_that_did_not_run_is_never_a_pass(self):
        result = fakes.review_result()
        record = self.judge_needs(gate_needs(json.dumps(result), security="false", switch_spec="true"))
        self.assertEqual((record["verdict"], verdict.conclusion(record)), ("ERROR", "failure"), record["error"])

    def test_c2_a_real_cap_refusal_before_the_spec_call_stays_a_budget_skip(self):
        """D18, D21: the pin for the other side of C2. A real cap refusal is the budget, and the machine checks decide."""
        result = fakes.review_result(budget_refused=True, limit="Spec call: API daily pace 5/5")
        record = self.judge_needs(gate_needs(json.dumps(result), security="false", switch_spec="true"))
        self.assertEqual((record["verdict"], record["title"], record["budget"]["skipped"]),
                         ("PASS", "T2 passed (review skipped: budget)", True), record["error"])
        failing = gate_needs(json.dumps(result), security="false", switch_spec="true", has_checks="true",
                             checks="dW5pdA==:dHJ1ZQ==")
        failing["checks"] = {"result": "success", "outputs": {"head": "h", "results": '[{"name":"unit","result":"fail"}]'}}
        self.assertEqual(self.judge_needs(failing)["verdict"], "FAIL", "the machine checks still decide")

    def test_c2_a_failed_lookup_before_the_spec_call_is_an_error(self):
        def claude(args, prompt, billing, runner):
            return reply("```json\n[]\n```", 0.5) if prompt.startswith("/code-review") else reply("done", 0.1)

        def unreadable(*a):
            raise RuntimeError("503 from the Actions API")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "RUNNER_TEMP": tmp, "HEAD_DIR": tmp, "BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m", "EFFORT": "medium",
                "SPEC_TEXT": json.dumps("## Done when\n- a\n"), "PACE": json.dumps(BUDGET), "SECURITY": "false",
                "GITHUB_REPOSITORY": "o/r", "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/c.yml@refs/heads/main"}), \
                mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
                mock.patch.object(review, "claude", claude), \
                mock.patch.object(fakes.github, "month_records", unreadable, create=True):
            out, _ = fakes.run(review.main)
            assert not verdict.parse_review(json.dumps(out))[1], verdict.parse_review(json.dumps(out))[1]
        record = self.judge_needs(gate_needs(json.dumps(out), security="false", switch_spec="true"))
        self.assertEqual((record["verdict"], verdict.conclusion(record)), ("ERROR", "failure"), record["error"])
        self.assertNotIn("spec_skipped", out)
        self.assertIn("budget read failed", out["error"])

    def test_c2_a_failed_lookup_while_posting_is_an_error(self):
        def unreadable(*a):
            raise RuntimeError("503 from the Actions API")
        record = self.judge_needs(gate_needs(json.dumps(fakes.review_result()), security="false"), month_records=unreadable)
        self.assertEqual((record["verdict"], verdict.conclusion(record)), ("ERROR", "failure"), record["error"])

    def test_c3_a_fail_whose_only_p0_was_trimmed_survives_a_failed_publish_and_stays_sticky(self):
        rows = [{"call": "bugs", "severity": "P1", "file": "a.py", "line": 1, "summary": "s" * 150, "failure": "f" * 300}
                for _ in range(1999)]
        rows.append({**rows[0], "severity": "P0", "summary": "the only P0"})
        first = fakes.GitHub(fail={"POST check-runs": [fakes.http_error(502)]})
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        month = mock.patch.object(fakes.github, "month_records", lambda *a: [(when, {"budget": BUDGET})])
        result = fakes.review_result(findings=rows)
        with fakes.installed(first, NEEDS=json.dumps(gate_needs(json.dumps(result), security="false"))), month:
            fakes.run(verdict.post)
        posted = verdict.parse_text(first.writes()[-1][2]["output"]["text"])
        rerun = fakes.GitHub(checks={"h": [fakes.check(1, posted, conclusion=first.writes()[-1][2]["conclusion"])]})
        clean = gate_needs(json.dumps(fakes.review_result()), security="false")
        with fakes.installed(rerun, NEEDS=json.dumps(clean)), month:
            fakes.run(verdict.post)
        again = verdict.parse_text(rerun.writes()[-1][2]["output"]["text"])
        self.assertEqual((len(first.writes()), posted["verdict"], posted.get("p0"), again["verdict"]), (2, "FAIL", 1, "FAIL"),
                         "the fallback posts the computed FAIL, and a clean rerun on the same head still sees it")
        self.assertNotIn("the only P0", json.dumps(posted["findings"]), "the P0 row itself was trimmed")


if __name__ == "__main__":
    unittest.main()
