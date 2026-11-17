import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
from tier import classify  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
