"""D18 as amended 2026-11-19: when the API budget refuses, the review runs on the Claude subscription."""
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "engine/claude-job"))
import fakes  # noqa: E402
import review  # noqa: E402
import tier  # noqa: E402
import verdict  # noqa: E402
from tier import ConfigError, settings  # noqa: E402
from verdict import budget_base, route  # noqa: E402

NOW = datetime(2026, 11, 18, 15, 0, tzinfo=timezone.utc)
CAPS = {"reviews_per_day": 5, "budget_month_usd": 100.0, "subscription_fallback": True, "subscription_per_day": 30}
TOKEN = "sk-" + "ant-oat01-TESTTOKEN"  # split: a whole token-shaped literal trips secret scanners


def totals(today=0, month=0.0, sub=0):
    return {"reviews_today": today, "month_usd": month, "subscription_today": sub}


class Config(unittest.TestCase):
    def test_no_block_is_fallback_off(self):
        s = settings({}, "dev")
        self.assertEqual((s["subscription_fallback"], s["subscription_per_day"]), (False, 0))

    def test_block_is_read(self):
        s = settings({"subscription": {"fallback": True, "reviews_per_day": 30}}, "dev")
        self.assertEqual((s["subscription_fallback"], s["subscription_per_day"]), (True, 30))

    def test_wrong_types_are_config_errors(self):
        for block in ("on", {"fallback": "yes", "reviews_per_day": 30}, {"fallback": True, "reviews_per_day": "30"},
                      {"fallback": True, "reviews_per_day": True}, {"fallback": True, "reviews_per_day": -1},
                      {"fallback": True, "reviews_per_day": 1.5}, {"fallback": True},
                      {"fallback": True, "reviews_per_day": 3, "reviews_per_month": 9}):
            with self.assertRaises(ConfigError, msg=block):
                settings({"subscription": block}, "dev")

    def test_fallback_off_needs_no_cap(self):
        self.assertEqual(settings({"subscription": {"fallback": False}}, "dev")["subscription_fallback"], False)

    def test_the_example_config_parses(self):
        import tomllib
        s = settings(tomllib.loads((ROOT / "examples/dotfiles.verification.toml").read_text()), "dev")
        self.assertTrue(s["subscription_fallback"])


class Route(unittest.TestCase):
    def test_api_while_both_api_limits_allow(self):
        self.assertEqual(route(totals(4, 99.9), CAPS, True), ("api", ""))

    def test_each_api_limit_moves_to_the_subscription(self):
        billing, why = route(totals(5, 0), CAPS, True)
        self.assertEqual(billing, "subscription")
        self.assertIn("API daily pace 5/5", why)
        billing, why = route(totals(0, 100.0), CAPS, True)
        self.assertEqual(billing, "subscription")
        self.assertIn("API month cap $100.00/$100.00", why)

    def test_reviews_per_day_0_turns_api_reviews_off(self):
        self.assertEqual(route(totals(), {**CAPS, "reviews_per_day": 0}, True)[0], "subscription")

    def test_no_subscription_when_off_tokenless_or_at_its_cap(self):
        for caps, token, sub, text in ((({**CAPS, "subscription_fallback": False}), True, 0, "subscription fallback off"),
                                       (CAPS, False, 0, "no subscription token"),
                                       (CAPS, True, 30, "subscription daily pace 30/30")):
            billing, why = route(totals(5, 0, sub), caps, token)
            self.assertIsNone(billing)
            self.assertIn("API daily pace 5/5", why)
            self.assertIn(text, why)

    def test_an_api_refusal_counts_as_an_api_limit(self):
        self.assertEqual(route(totals(), CAPS, True, refused="API spend limit refused the call"),
                         ("subscription", "API spend limit refused the call"))

    def test_old_budget_without_subscription_keys_never_routes_there(self):
        self.assertIsNone(route(totals(5, 0), {"reviews_per_day": 5, "budget_month_usd": 100.0}, True)[0])


class Totals(unittest.TestCase):
    def test_old_records_read_as_api_with_no_subscription(self):
        records = [("2026-11-18T10:00:00Z", {"budget": {"reviews_today": 2, "month_usd": 30.0}})]
        self.assertEqual(budget_base(records, NOW), totals(2, 30.0, 0))

    def test_subscription_today_resets_by_day_and_carries_within_it(self):
        rec = {"budget": totals(1, 5.0, 7)}
        self.assertEqual(budget_base([("2026-11-18T10:00:00Z", rec)], NOW), totals(1, 5.0, 7))
        self.assertEqual(budget_base([("2026-11-17T23:00:00Z", rec)], NOW), totals(0, 5.0, 0))


class Judge(unittest.TestCase):
    """The gate job writes running totals: API totals stay API-only, the subscription count rides beside them."""

    def judge(self, review_result, prior=totals(3, 30.0, 4), budget_extra=None):
        budget = {**CAPS, "skipped": False, **(budget_extra or {})}
        tier_out = {"base_sha": "b", "mode": "shadow", "tiers": "T1", "has_checks": "false", "review": "true",
                    "budget": json.dumps(budget), "switch_spec": "false", "reasons": "r"}
        needs = {"start": {"result": "success", "outputs": {"base_sha": "b"}},
                 "tier": {"result": "success", "outputs": tier_out},
                 "checks": {"result": "skipped", "outputs": {}},
                 "review": {"result": "success", "outputs": {"head": "h", "result": json.dumps(review_result)}}}
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with fakes.installed(fakes.GitHub()), mock.patch.object(fakes.github, "month_records",
                                                                lambda *a: [(when, {"budget": prior})]):
            (record, body), log = fakes.run(verdict.judge, fakes.github, needs, "o/r", "h", "url", "dev")
        return record, body, log

    def test_a_subscription_review_never_adds_to_month_usd(self):
        record, body, log = self.judge({"findings": [], "spec": None, "cost_usd": 0.0, "subscription_cost_usd": 0.8,
                                        "billing": "subscription", "error": None, "budget_refused": False})
        b = record["budget"]
        self.assertEqual((b["reviews_today"], b["month_usd"], b["subscription_today"]), (3, 30.0, 5))
        self.assertEqual((record["billing"], record["cost_usd"], record["subscription_cost_usd"]), ("subscription", 0.0, 0.8))
        self.assertIn("billing: subscription", body["output"]["summary"])
        self.assertIn("5 subscription reviews today", body["output"]["summary"])

    def test_an_api_review_carries_the_subscription_count(self):
        record, _, _ = self.judge({"findings": [], "spec": None, "cost_usd": 0.5, "billing": "api", "error": None,
                                   "budget_refused": False})
        b = record["budget"]
        self.assertEqual((b["reviews_today"], b["month_usd"], b["subscription_today"]), (4, 30.5, 4))
        self.assertEqual(record["billing"], "api")

    def test_a_mixed_run_counts_once_in_each(self):
        record, _, _ = self.judge({"findings": [], "spec": None, "cost_usd": 0.5, "subscription_cost_usd": 0.3,
                                   "billing": "api+subscription", "error": None, "budget_refused": False})
        b = record["budget"]
        self.assertEqual((b["reviews_today"], b["month_usd"], b["subscription_today"]), (4, 30.5, 5))

    def test_the_record_says_the_api_refused(self):
        record, body, _ = self.judge({"findings": [], "spec": None, "cost_usd": 0.0, "subscription_cost_usd": 0.4,
                                      "billing": "subscription", "refused": "api spend limit", "error": None,
                                      "budget_refused": False})
        self.assertEqual(record["refused"], "api spend limit")
        self.assertIn("billing: subscription (API refused: api spend limit)", body["output"]["summary"])

    def test_a_skip_names_the_limit(self):
        tier_budget = {**CAPS, "skipped": True, "limit": "API daily pace 5/5; subscription fallback off"}
        record = verdict.decide(head_sha="h", base_sha="b", tiers="T1", mode="shadow", switch_spec=False, machine=[],
                                review=None, budget={**totals(5, 1.0), **tier_budget}, errors=[], prior=[])
        text = verdict.summary(record, "none (review skipped: budget)", "r", "url")
        self.assertIn("budget: review skipped: budget (API daily pace 5/5; subscription fallback off)", text)
        self.assertEqual((record["title"], record["billing"]), ("T1 passed (review skipped: budget)", None))


class TierRoute(unittest.TestCase):
    """tier.py github picks the route from the base toml, the month's records and whether the caller passed a token."""

    def main(self, config, today=5, month=1.0, sub=0, token="true", fail=None):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {"schema": 1, "verdict": "PASS", "budget": totals(today, month, sub)}
        fake = fakes.GitHub(config=config, files=[{"filename": "a.py", "additions": 3, "deletions": 0}],
                            workflow_runs=[{"head_sha": "x", "created_at": now}],
                            checks={"x": [fakes.check(1, record, now)]}, fail=fail)
        env = {"SUBSCRIPTION_TOKEN_SET": token} if token is not None else {}
        with tempfile.NamedTemporaryFile("r") as out, fakes.installed(fake, GITHUB_OUTPUT=out.name, **env):
            code, log = fakes.run(tier.github_main)
            outputs = dict(line.split("=", 1) for line in Path(out.name).read_text().splitlines() if "=" in line)
        return outputs, json.loads(outputs["budget"]), log

    ON = 'reviews_per_day = 5\nbudget_month_usd = 100\n[subscription]\nfallback = true\nreviews_per_day = 30\n'

    def test_api_under_its_limits(self):
        out, budget, _ = self.main(self.ON, today=1)
        self.assertEqual((out["review"], budget["route"], budget["skipped"]), ("true", "api", False))

    def test_api_pace_reached_runs_on_the_subscription(self):
        out, budget, log = self.main(self.ON, today=5)
        self.assertEqual((out["review"], out["skip"], budget["route"]), ("true", "", "subscription"))
        self.assertEqual(budget["subscription_today"], 0)
        self.assertIn("API daily pace 5/5", budget["limit"])
        self.assertNotIn(TOKEN, log)

    def test_month_cap_reached_runs_on_the_subscription(self):
        self.assertEqual(self.main(self.ON, today=0, month=100.0)[1]["route"], "subscription")

    def test_skipped_when_the_subscription_may_not_run(self):
        for config, token, sub, why in ((self.ON, "false", 0, "no subscription token"),
                                        (self.ON, None, 0, "no subscription token"),
                                        (self.ON, "true", 30, "subscription daily pace 30/30"),
                                        (self.ON.replace("fallback = true", "fallback = false"), "true", 0,
                                         "subscription fallback off"),
                                        ('reviews_per_day = 5\n', "true", 0, "subscription fallback off")):
            out, budget, _ = self.main(config, today=5, sub=sub, token=token)
            self.assertEqual((out["review"], out["skip"], budget["skipped"], budget["route"]),
                             ("false", "review skipped: budget", True, None), why)
            self.assertIn(why, budget["limit"])

    def test_a_budget_read_failure_stays_closed(self):
        out, budget, _ = self.main(self.ON, fail={"GET actions/workflows": [fakes.http_error(403)]})
        self.assertEqual((out["review"], out["skip"], budget["route"]), ("false", "review skipped: budget", None))
        self.assertIn("budget read failed", budget["read_error"])

    def test_a_bad_block_is_a_config_error(self):
        out, _, _ = self.main(self.ON.replace("reviews_per_day = 30", 'reviews_per_day = "30"'))
        self.assertIn("subscription", out.get("error", ""))


SPEND_LIMIT = json.dumps({"is_error": True, "subtype": "success", "total_cost_usd": 0, "result":
                          "API Error: 400 You have reached your specified API usage limits. You will regain access on 2026-12-01."})
CREDIT = json.dumps({"is_error": False, "subtype": "success", "total_cost_usd": 0, "result": "Credit balance is too low"})
OK_BUGS = json.dumps({"is_error": False, "result": "```json\n[]\n```", "total_cost_usd": 0.4})
OK_SPEC = json.dumps({"is_error": False, "result": "done", "total_cost_usd": 0.3,
                      "structured_output": {"answer": "Yes", "items": [{"n": 1, "item": "a", "status": "Yes"}]}})
PLAN_LIMITS = (json.dumps({"is_error": True, "subtype": "success", "total_cost_usd": 0,
                           "result": "Claude AI usage limit reached|1763600000"}),
               json.dumps({"is_error": False, "subtype": "success", "total_cost_usd": 0,
                           "result": "You\u2019ve hit your limit \u00b7 resets 3pm (UTC)"}))
REJECTED = json.dumps({"is_error": True, "subtype": "success", "total_cost_usd": 0,
                       "result": 'Failed to authenticate. API Error: 401 {"type":"error","error":{"type":"authentication_error",'
                                 '"message":"OAuth access token is invalid."}}'})


class MidRun(unittest.TestCase):
    """An API call refused for spend or credit is retried once on the subscription when the subscription may run."""

    def run_main(self, replies, pace=None, prior=totals(5, 1.0, 0), token=TOKEN, spec=False, reads=None):
        calls, self.prompts, self.args = [], [], []

        def claude(args, prompt, billing, runner):
            calls.append(billing)
            self.prompts.append(prompt)
            self.args.append(args)
            reply = replies[len(calls) - 1]
            return (1, *reply) if isinstance(reply, tuple) else (0, reply, "")
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        reads = iter(reads or [])

        def month_records(*a):
            outcome = next(reads, None)
            if isinstance(outcome, Exception):
                raise outcome
            return [(when, {"budget": prior})]
        env = {"BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m", "EFFORT": "medium", "GITHUB_REPOSITORY": "o/r",
               "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/c.yml@refs/heads/main",
               "PACE": json.dumps(pace or {**CAPS, "route": "api"}), "SUBSCRIPTION_TOKEN": token,
               "SPEC_TEXT": json.dumps("## Done when\n- a\n" if spec else "")}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {**env, "RUNNER_TEMP": tmp, "HEAD_DIR": tmp}), \
                mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
                mock.patch.object(review, "claude", claude), \
                mock.patch.object(fakes.github, "month_records", month_records, create=True):
            out, log = fakes.run(review.main)
            self.assertNotIn("SUBSCRIPTION_TOKEN", os.environ, "the token leaves the process env before any call")
        return calls, out, log

    def test_spend_limit_is_retried_on_the_subscription(self):
        calls, out, log = self.run_main([SPEND_LIMIT, OK_BUGS])
        self.assertEqual(calls, ["api", "subscription"])
        self.assertEqual((out["billing"], out["budget_refused"], out["error"]), ("subscription", False, None))
        self.assertEqual((out["cost_usd"], out["subscription_cost_usd"]), (0.0, 0.4))
        self.assertIn("notional", log)

    def test_credit_error_is_retried_on_the_subscription(self):
        calls, out, _ = self.run_main([CREDIT, OK_BUGS])
        self.assertEqual((calls, out["billing"], out["error"]), (["api", "subscription"], "subscription", None))

    def test_no_retry_when_the_subscription_may_not_run(self):
        for pace, token, prior in (({**CAPS, "route": "api", "subscription_fallback": False}, TOKEN, totals()),
                                   ({**CAPS, "route": "api"}, "", totals()),
                                   ({**CAPS, "route": "api"}, TOKEN, totals(sub=30))):
            calls, out, _ = self.run_main([SPEND_LIMIT], pace=pace, token=token, prior=prior)
            self.assertEqual((calls, out["budget_refused"], out["billing"]), (["api"], True, None))
            calls, out, _ = self.run_main([CREDIT], pace=pace, token=token, prior=prior)
            self.assertEqual(calls, ["api"])
            self.assertIn("Credit balance", out["error"])

    def test_the_tier_route_runs_on_the_subscription_with_no_token_exchange(self):
        with mock.patch.object(review, "exchange", side_effect=AssertionError("no exchange on the subscription")):
            calls, out, _ = self.run_main([OK_BUGS], pace={**CAPS, "route": "subscription"})
        self.assertEqual((calls, out["billing"], out["error"]), (["subscription"], "subscription", None))

    def test_the_standards_file_is_readable_on_every_route(self):
        """The subscription call's cwd is empty, so the base's standards file is allowed by its own path."""
        seen = []
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "RUNNER_TEMP": tmp, "HEAD_DIR": tmp, "BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m", "EFFORT": "medium",
                "STANDARDS": "/base/CODING_STANDARDS.md", "PACE": json.dumps({**CAPS, "route": "subscription"}),
                "SUBSCRIPTION_TOKEN": TOKEN}), mock.patch.object(review, "prepare"), \
                mock.patch.object(review, "claude", lambda args, *a: seen.append(args) or (0, OK_BUGS, "")):
            fakes.run(review.main)
        allowed = seen[0][seen[0].index("--allowedTools") + 1]
        self.assertIn("Read(//base/CODING_STANDARDS.md)", allowed)

    def test_a_rejected_token_is_an_error_not_a_budget_skip(self):
        calls, out, _ = self.run_main([SPEND_LIMIT, REJECTED])
        self.assertEqual(calls, ["api", "subscription"])
        self.assertFalse(out["budget_refused"])
        self.assertIn("subscription token rejected", out["error"])

    def test_a_failed_subscription_call_still_counts_against_its_cap(self):
        failed = json.dumps({"is_error": True, "subtype": "error_max_budget_usd", "result": "", "total_cost_usd": 0.2})
        for reply in (failed, json.dumps({"is_error": False, "result": "prose, no block", "total_cost_usd": 0.2})):
            _, out, _ = self.run_main([reply], pace={**CAPS, "route": "subscription"})
            self.assertTrue(out["error"])
            self.assertEqual((out["billing"], out["subscription_cost_usd"]), ("subscription", 0.2))

    def test_a_refused_api_call_is_not_billed_to_the_api(self):
        _, out, _ = self.run_main([SPEND_LIMIT, OK_BUGS])
        self.assertEqual(out["billing"], "subscription")

    def test_an_api_refusal_with_401_or_oauth_in_its_stderr_still_retries(self):
        for stderr in ("upstream said 401 earlier", "OAuth token refresh skipped"):
            calls, out, _ = self.run_main([(SPEND_LIMIT, stderr), OK_BUGS])
            self.assertEqual((calls, out["error"]), (["api", "subscription"], None), stderr)

    def test_a_spent_subscription_plan_is_a_budget_skip_not_an_error(self):
        for reply in PLAN_LIMITS:
            _, out, _ = self.run_main([reply], pace={**CAPS, "route": "subscription"})
            self.assertEqual((out["budget_refused"], out["error"]), (True, None), reply)
            self.assertIn("subscription plan limit", out["limit"])
        _, out, _ = self.run_main([SPEND_LIMIT, PLAN_LIMITS[0]])
        self.assertEqual((out["budget_refused"], out["error"]), (True, None))
        self.assertIn("API spend limit refused the call", out["limit"])
        self.assertIn("subscription plan limit", out["limit"])

    def test_the_spec_call_stays_off_the_api_after_the_bugs_call_was_refused(self):
        calls, out, _ = self.run_main([SPEND_LIMIT, OK_BUGS, OK_SPEC], prior=totals(0, 0.0, 0), spec=True)
        self.assertEqual(calls, ["api", "subscription", "subscription"])
        self.assertEqual((out["error"], out["billing"], out["refused"]), (None, "subscription", "api spend limit"))

    def test_the_refusal_survives_a_failed_budget_reread(self):
        _, out, _ = self.run_main([SPEND_LIMIT], reads=[RuntimeError("503")])
        self.assertTrue(out["budget_refused"])
        self.assertIn("API spend limit refused the call", out["limit"])
        self.assertIn("budget read failed", out["limit"])
        self.assertEqual(out["refused"], "api spend limit")
        _, out, _ = self.run_main([CREDIT, OK_BUGS])
        self.assertEqual(out["refused"], "api credit")

    def test_the_prompts_name_where_the_base_is_on_every_route(self):
        for pace in ({**CAPS, "route": "api"}, {**CAPS, "route": "subscription"}):
            self.run_main([OK_BUGS, OK_SPEC], pace=pace, prior=totals(0 if pace["route"] == "api" else 5, 0.0, 0),
                          spec=True)
            base = str(Path.cwd())
            for prompt, args in zip(self.prompts, self.args):
                self.assertNotIn("working directory", prompt)
                self.assertIn(f"checked out at {base}", prompt)
                self.assertIn(f"Read(/{base}/**)", args[args.index("--allowedTools") + 1])

    def test_spec_call_rechecks_the_subscription_cap_on_that_route(self):
        calls, out, _ = self.run_main([OK_BUGS], pace={**CAPS, "route": "subscription"}, prior=totals(5, 1.0, 30),
                                      spec=True)
        self.assertEqual(calls, ["subscription"])
        self.assertIn("subscription daily pace 30/30", out["spec_skipped"])


class Argv(unittest.TestCase):
    """The subscription call cannot use --bare (it ignores CLAUDE_CODE_OAUTH_TOKEN), so it rebuilds the isolation."""

    def call(self, billing):
        seen = {}

        def run(cmd, **kw):
            seen.update(cmd=cmd, **kw)
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(review.subprocess, "run", run), \
                mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k", "ANTHROPIC_AUTH_TOKEN": "t", "GH_TOKEN": "g",
                                             "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "a", "CLAUDE_CODE_OAUTH_TOKEN": "stray"}):
            runner = review.Runner(token_file=Path(d) / "secret/token", home=Path(d) / "home", cwd=Path(d) / "cwd",
                                   oauth=TOKEN)
            runner.cwd.mkdir()
            fakes.run(review.claude, ["--model", "m"], "PROMPT", billing, runner)
            seen["cwd_dir"] = runner.cwd
        return seen

    def test_subscription_argv_and_env(self):
        seen = self.call("subscription")
        cmd, env = seen["cmd"], seen["env"]
        self.assertNotIn("--bare", cmd)
        for flag in ("--strict-mcp-config", "--safe-mode", "--no-session-persistence"):
            self.assertIn(flag, cmd)
        self.assertFalse(any("apiKeyHelper" in a for a in cmd))
        self.assertFalse(any(TOKEN in a for a in cmd), "the token never reaches argv")
        self.assertEqual(env["CLAUDE_CODE_OAUTH_TOKEN"], TOKEN)
        self.assertEqual(env["ENABLE_TOOL_SEARCH"], "false")
        for gone in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GH_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            self.assertNotIn(gone, env)
        self.assertEqual(Path(seen["cwd"]).parent, seen["cwd_dir"], "each call gets its own dir under the cwd root")
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(Path(env["HOME"]) / ".claude"))

    def test_api_argv_keeps_bare_and_never_sees_the_token(self):
        seen = self.call("api")
        self.assertIn("--bare", seen["cmd"])
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", seen["env"])
        self.assertNotIn("ANTHROPIC_API_KEY", seen["env"])
        self.assertFalse(any(TOKEN in a for a in seen["cmd"]))

    def test_two_subscription_calls_in_a_row_each_get_an_empty_cwd(self):
        cwds = []

        def run(cmd, cwd=None, **kw):
            self.assertEqual(list(Path(cwd).iterdir()), [])
            cwds.append(cwd)
            (Path(cwd) / ".claude").mkdir()  # whatever a call leaves behind
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(review.subprocess, "run", run):
            runner = review.Runner(token_file=Path(d) / "t", home=Path(d) / "home", cwd=Path(d) / "cwd", oauth=TOKEN)
            runner.cwd.mkdir()
            for _ in range(2):
                fakes.run(review.claude, ["--model", "m"], "PROMPT", "subscription", runner)
        self.assertEqual(len(set(cwds)), 2)

    def test_a_claude_md_above_the_empty_cwd_refuses_the_subscription_call(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "CLAUDE.md").write_text("x")
            cwd = Path(d) / "review/cwd"
            cwd.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "CLAUDE.md"):
                review.isolated_cwd(cwd)
            (Path(d) / "CLAUDE.md").unlink()
            self.assertEqual(review.isolated_cwd(cwd), cwd)


class GateYml(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github/workflows/gate.yml").read_text()
        self.action = (ROOT / "engine/claude-job/action.yml").read_text()

    def test_the_secret_is_optional_and_reaches_only_the_review_step(self):
        self.assertRegex(self.text, r"\n      claude_code_oauth_token:\n        description:.*\n(?:          .+\n)*        required: false\n")
        uses = [line.strip() for line in self.text.splitlines() if "secrets.claude_code_oauth_token" in line]
        self.assertEqual(uses, ["SUBSCRIPTION_TOKEN_SET: ${{ secrets.claude_code_oauth_token != '' }}",
                                "claude_code_oauth_token: ${{ secrets.claude_code_oauth_token }}"])
        from test_gate_yml import job
        self.assertIn("SUBSCRIPTION_TOKEN_SET", job(self.text, "tier"))
        self.assertIn("claude_code_oauth_token: ${{ secrets.claude_code_oauth_token }}", job(self.text, "review"))
        self.assertNotIn("inherit", self.text)

    def test_the_action_passes_the_token_to_the_review_step_only_and_the_stub_is_gone(self):
        self.assertEqual(re.findall(r".*inputs\.claude_code_oauth_token.*", self.action),
                         ["        SUBSCRIPTION_TOKEN: ${{ inputs.claude_code_oauth_token }}"])
        for gone in ("subscription_fallback", "credit_error", "not built"):
            self.assertNotIn(gone, self.action)
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", self.action)


if __name__ == "__main__":
    unittest.main()
