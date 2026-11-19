import json
import os
import sys
import tempfile
import tomllib
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
import tier  # noqa: E402
from tier import ConfigError, classify, settings, switch  # noqa: E402
import fakes  # noqa: E402
from verdict import render_text  # noqa: E402

RULES = tomllib.load(open(ROOT / "examples/dotfiles.verification.toml", "rb"))["tiers"]


def f(name, lines=10, prev=None):
    d = {"filename": name, "additions": lines, "deletions": 0}
    if prev:
        d["previous_filename"] = prev
    return d


class Tier(unittest.TestCase):
    def tiers(self, *files, truncated=False):
        return classify(list(files), RULES, truncated).tiers

    def test_docs_only_is_t0(self):
        self.assertEqual(self.tiers(f("README.md", 400), f("docs/x.md")), ["T0"])

    def test_small_code_is_t1(self):
        self.assertEqual(self.tiers(f("claude/scripts/foo.py", 50)), ["T1"])

    def test_300_code_lines_is_t2_but_docs_do_not_count(self):
        self.assertEqual(self.tiers(f("a.py", 299), f("b.md", 500)), ["T1"])
        self.assertEqual(self.tiers(f("a.py", 200), f("b.sh", 100)), ["T2"])

    def test_risk_path_is_t2(self):
        self.assertEqual(self.tiers(f("claude/hooks/scripts/x.sh", 1)), ["T2"])
        self.assertEqual(self.tiers(f(".github/workflows/verification.yml", 1)), ["T2"])
        self.assertEqual(self.tiers(f("claude/spine/core.py", 1)), ["T2"])

    def test_risk_wins_over_docs(self):
        self.assertEqual(self.tiers(f("claude/hooks/checks.md", 5)), ["T2"])

    def test_skill_is_tp_only(self):
        self.assertEqual(self.tiers(f("claude/skills/x/SKILL.md")), ["TP"])
        self.assertEqual(self.tiers(f("claude/rules/standing-rules.md")), ["TP"])

    def test_union_of_tiers(self):
        self.assertEqual(self.tiers(f("claude/hooks/scripts/x.sh"), f("claude/skills/x/SKILL.md")), ["T2", "TP"])
        self.assertEqual(self.tiers(f("x.py"), f("CLAUDE.md")), ["T1", "TP"])

    def test_rename_out_of_risk_path_still_t2(self):
        self.assertEqual(self.tiers(f("tmp/x.sh", 0, prev="claude/hooks/scripts/x.sh")), ["T2"])

    def test_rename_into_a_prompt_name_keeps_the_old_tier(self):
        self.assertEqual(self.tiers(f("claude/skills/x/SKILL.md", 0, prev="claude/hooks/scripts/x.sh")), ["T2", "TP"])
        self.assertEqual(self.tiers(f("claude/skills/x/SKILL.md", 0, prev="claude/x.py")), ["T1", "TP"])

    def test_truncated_file_list_owes_every_tier(self):
        self.assertEqual(self.tiers(f("README.md"), truncated=True), ["T2", "TP"])



SECTION = "## Acceptance criteria\n\n- [ ] it works\n"
PR_OPENED = "2026-11-18T12:00:00Z"


def issue(created, body, edits=()):
    return {"number": 7, "createdAt": created, "body": body, "edits": [{"editedAt": t, "diff": b} for t, b in edits]}


class Switch(unittest.TestCase):
    """D8: Spec call only for an issue created before the PR whose body had the section when the PR opened."""

    def test_created_before_with_a_section(self):
        self.assertIn("it works", switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "Intro\n\n" + SECTION)]))

    def test_created_after_the_pr(self):
        self.assertEqual(switch(PR_OPENED, [issue("2026-11-18T13:00:00Z", SECTION)]), "")

    def test_section_added_after_the_pr_opened(self):
        edits = [("2026-11-18T14:00:00Z", "Intro\n\n" + SECTION), ("2026-11-17T00:00:00Z", "Intro")]
        self.assertEqual(switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "Intro\n\n" + SECTION, edits)]), "")

    def test_no_section(self):
        self.assertEqual(switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "Just a bug report.")]), "")

    def test_section_stops_at_the_next_heading(self):
        got = switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "## Done when\n- a\n## Notes\n- b\n")])
        self.assertIn("- a", got)
        self.assertNotIn("- b", got)

    def test_bold_heading_with_a_checklist(self):
        """Fix 9: a bold Done when line (any case, optional colon) followed by a checklist."""
        body = "Intro\r\n\r\n**DONE WHEN:**\r\n- [ ] it works\r\n- [ ] it is fast\r\n\r\nNotes after the list.\r\n"
        got = switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", body)])
        self.assertIn("it works", got)
        self.assertIn("it is fast", got)
        self.assertNotIn("Notes after", got)
        self.assertEqual(tier.done_items(got), ["it works", "it is fast"])
        self.assertIn("ok", switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "**Acceptance criteria**:\n\n1. ok\n")]))

    def test_bold_heading_without_a_list_is_no_section(self):
        self.assertEqual(switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "**Done when** it ships.\n")]), "")
        self.assertEqual(switch(PR_OPENED, [issue("2026-11-17T00:00:00Z", "**Done when**\nIt ships.\n")]), "")


class Settings(unittest.TestCase):
    def test_old_mode_value_names_shadow(self):
        with self.assertRaisesRegex(ConfigError, 'mode = "shadow"'):
            settings({"mode": "obs" + "erve"}, "dev")

    def test_live_checks(self):
        self.assertEqual(settings({"live_checks": "machine"}, "dev")["live_checks"], "machine")
        self.assertEqual(settings({"live_checks": "machine", "enforce_branches": ["dev"]}, "dev")["live_checks"], "owed")
        with self.assertRaises(ConfigError):
            settings({"live_checks": "some"}, "dev")

    def test_mode_defaults_to_shadow(self):
        self.assertEqual(settings({}, "dev")["mode"], "shadow")
        self.assertEqual(settings({"mode": "enforce"}, "dev")["mode"], "enforce")


class GitHubMain(unittest.TestCase):
    """tier.py github end to end against a fake GitHub API (fixes 1, 4, 8, 12)."""

    def main(self, fake):
        with tempfile.NamedTemporaryFile("r", suffix=".out") as out, fakes.installed(fake, GITHUB_OUTPUT=out.name):
            code, log = fakes.run(tier.github_main)
            outputs = dict(line.split("=", 1) for line in Path(out.name).read_text().splitlines() if "=" in line)
        return code, log, outputs

    def test_config_error_in_shadow_exits_0_with_the_error_output(self):
        code, _, out = self.main(fakes.GitHub(config='mode = "shadow"\nlive_checks = "some"\n'))
        self.assertEqual((code, out.get("mode"), out.get("has_checks")), (0, "shadow", "false"))
        self.assertIn("live_checks", out.get("error", ""))

    def test_config_error_keeps_a_raw_enforce_mode(self):
        _, _, out = self.main(fakes.GitHub(config='mode = "enforce"\nlive_checks = "some"\n'))
        self.assertEqual(out.get("mode"), "enforce")

    def test_compare_5xx_exits_0_with_the_error_output(self):
        code, _, out = self.main(fakes.GitHub(fail={"GET /compare/": [fakes.http_error(502)]}))
        self.assertEqual((code, out.get("mode")), (0, "shadow"))
        self.assertIn("502", out.get("error", ""))

    def test_t2_bugs_level_defaults_to_medium(self):
        """Fix 12: /code-review medium at every tier."""
        _, _, out = self.main(fakes.GitHub(config='live_checks = "machine"\n', files=[f(".github/workflows/x.yml")]))
        self.assertEqual((out["tiers"], out["review_level"]), ("T2", "medium"))

    def test_example_config_asks_medium_at_t2(self):
        config = tomllib.loads((ROOT / "examples/dotfiles.verification.toml").read_text())["review"]
        self.assertEqual((config["t1_level"], config["t2_level"]), ("medium", "medium"))

    def paid_record(self, today):
        return {"schema": 1, "verdict": "PASS", "budget": {"reviews_today": today, "month_usd": 12.0}}

    def test_budget_counts_a_run_whose_head_is_no_longer_on_any_pr(self):
        """Fix 8: the newest record sits on a head force-pushed away; the PRs list no such commit."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fake = fakes.GitHub(files=[f("a.py")], workflow_runs=[{"head_sha": "gone", "created_at": now}],
                            checks={"gone": [fakes.check(1, self.paid_record(5), now)]})
        code, log, out = self.main(fake)
        self.assertEqual((code, out["review"], out["skip"]), (0, "false", "review skipped: budget"))
        self.assertEqual(json.loads(out["budget"])["reviews_today"], 5)

    def test_budget_read_failure_skips_the_paid_review_and_is_an_error(self):
        """Fix 8: fail closed, and say the read failed. A read failure is not a refusal: the verdict is ERROR."""
        fake = fakes.GitHub(files=[f("a.py")], fail={"GET actions/workflows": [fakes.http_error(403)]})
        code, log, out = self.main(fake)
        self.assertEqual((code, out["review"], out["skip"]), (0, "false", "budget unreadable"))
        self.assertIn("budget read failed", out["error"])

    def test_issue_text_reaches_the_log_only_inside_stop_commands(self):
        """Fix 4: the outputs dump holds the done-when text."""
        fake = fakes.GitHub(files=[f("a.py")])
        closing = {"data": {"repository": {"pullRequest": {"createdAt": "2026-11-18T00:00:00Z", "closingIssuesReferences": {
            "nodes": [{"number": 3, "createdAt": "2026-11-17T00:00:00Z", "userContentEdits": {"nodes": []},
                       "body": "## Done when\n- ISSUE-TEXT ::add-mask::x\n"}]}}}}}
        real = fake.api
        fake.api = lambda path, method="GET", body=None, raw=False: (
            closing if path == "graphql" and "closingIssuesReferences" in body["query"] else real(path, method, body, raw))
        _, log, out = self.main(fake)
        self.assertEqual(out["switch_spec"], "true")
        self.assertEqual(fakes.outside_stop_commands(log, "ISSUE-TEXT"), [])


if __name__ == "__main__":
    unittest.main()
