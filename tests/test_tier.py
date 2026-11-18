import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
from tier import ConfigError, classify, settings, switch  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
