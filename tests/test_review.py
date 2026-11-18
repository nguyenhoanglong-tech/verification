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
        plain = "API Error: 400 You have reached your specified API usage limits. You will regain access on 2026-12-01."
        self.assertEqual(failure_kind(outcome(1, plain, "")[1]), "budget", "the CLI's plain error text is read too")
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

    def test_unparseable_output_is_logged_inside_stop_commands(self):
        lines = ["MODEL-TEXT", "::error file=a.py::MODEL-LINE-2", "::set-output name=x::MODEL-LINE-3"]
        cli = json.dumps({"is_error": False, "subtype": "success", "num_turns": 0, "local_command": "code_review",
                          "result": "\n".join(lines), "structured_output": None, "total_cost_usd": 0.13})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "RUNNER_TEMP": tmp, "HEAD_DIR": tmp, "BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m",
                "EFFORT": "medium"}), \
                mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
                mock.patch.object(review, "claude", lambda *a: (0, cli, "")):
            out, log = fakes.run(review.main)
        self.assertIn("unparseable output", out["error"])
        self.assertIn("MODEL-TEXT", log)
        self.assertIn('"local_command": "code_review"', log)
        for line in lines:
            self.assertIn(line, log)
            self.assertEqual(fakes.outside_stop_commands(log, line), [], line)


class SpecBudget(unittest.TestCase):
    """Fix 7: the budget is read again right before the Spec call."""

    def test_spec_call_skipped_when_the_pace_is_reached_after_the_bugs_call(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        records = [(now, {"budget": {"reviews_today": 5, "month_usd": 10.0}})]
        bugs = json.dumps({"is_error": False, "result": "```json\n[]\n```", "total_cost_usd": 1.5})
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


class BugsCall(unittest.TestCase):
    """/code-review runs as a forked agent. On CLI 2.1.326 the fork gets the StructuredOutput tool from --json-schema
    but its payload never reaches the result, and --append-system-prompt-file never reaches the fork at all."""

    FINDING = {"severity": "P0", "file": "a.py", "line": 5, "summary": "off by one", "failure_scenario": "n=0 fails"}

    def run_main(self, cwd, bugs_text="```json\n[]\n```"):
        """(calls, the engine's returned record, log) for one run with a Bugs result text and a passing Spec result."""
        calls = {}

        def claude(args, prompt, token_file, home):
            name = "spec" if "Done-when" in prompt else "bugs"
            calls[name] = (args, prompt)
            spec = {"answer": "Yes", "items": [{"item": "a", "status": "Yes"}]}
            return 0, json.dumps({"is_error": False, "result": bugs_text if name == "bugs" else "done",
                                  "total_cost_usd": 0.1, **({"structured_output": spec} if name == "spec" else {})}), ""
        old = os.getcwd()
        os.chdir(cwd)
        try:
            with mock.patch.dict(os.environ, {
                    "RUNNER_TEMP": cwd, "HEAD_DIR": cwd, "BASE_SHA": "b", "ANTHROPIC": "{}", "MODEL": "m",
                    "EFFORT": "medium", "SPEC_TEXT": json.dumps("## Done when\n- a\n"), "PACE": "{}"}), \
                    mock.patch.object(review, "prepare"), mock.patch.object(review, "exchange", return_value=""), \
                    mock.patch.object(review, "spec_budget", return_value=""), \
                    mock.patch.object(review, "claude", claude):
                out, log = fakes.run(review.main)
        finally:
            os.chdir(old)
        return calls, out, log

    def run_in_tmp(self, bugs_text):
        with tempfile.TemporaryDirectory() as d:
            return self.run_main(d, bugs_text)

    def test_bugs_call_returns_its_findings_as_text(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "CODING_STANDARDS.md").write_text("R1 rule\n")
            calls = self.run_main(d)[0]
        bugs_args, spec_args = calls["bugs"][0], calls["spec"][0]
        self.assertNotIn("--json-schema", bugs_args)
        self.assertNotIn("--append-system-prompt-file", bugs_args)
        self.assertIn("--json-schema", spec_args)

    def test_bugs_prompt_names_the_standards_file_by_absolute_path(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "CODING_STANDARDS.md").write_text("R1 rule\n")
            prompt = self.run_main(d)[0]["bugs"][1]
            self.assertIn(f"Read {Path(d).resolve() / 'CODING_STANDARDS.md'},", prompt)

    def test_bugs_prompt_requires_one_fenced_json_findings_array(self):
        prompt = self.run_in_tmp("```json\n[]\n```")[0]["bugs"][1]
        self.assertTrue(prompt.startswith("/code-review medium "), prompt[:40])
        self.assertIn("exactly one fenced ```json block", prompt)
        self.assertIn("`[]` when there are none", prompt)
        self.assertIn("The block holds a JSON array of your findings", prompt)
        for field in ("severity", "file", "line", "summary", "failure_scenario"):
            self.assertIn(f'"{field}"', prompt)

    def test_record_holds_the_findings_of_a_fenced_array(self):
        text = f"An empty list prints as:\n```\n[]\n```\nTwo notes.\n```json\n{json.dumps([self.FINDING])}\n```"
        _, out, _ = self.run_in_tmp(text)
        self.assertIsNone(out["error"])
        self.assertEqual([(f["file"], f["line"], f["severity"], f["summary"]) for f in out["findings"]],
                         [("a.py", 5, "P0", "off by one")])

    def test_record_keeps_the_spec_result_when_both_calls_run(self):
        text = f'Shape:\n```json\n{{"file": "x", "line": 1}}\n```\n```json\n{json.dumps([self.FINDING])}\n```'
        _, out, _ = self.run_in_tmp(text)
        self.assertIsNone(out["error"])
        self.assertEqual([f["file"] for f in out["findings"]], ["a.py"])
        self.assertEqual((out["spec"]["answer"], out["spec"]["items"][0]["status"]), ("Yes", "Yes"))
        self.assertAlmostEqual(out["cost_usd"], 0.2)

    def test_prose_output_is_an_error_with_the_result_logged(self):
        _, out, log = self.run_in_tmp("PROSE-ONLY: the diff looks fine to me.")
        self.assertTrue((out["error"] or "").startswith("bugs call: unparseable output"), out["error"])
        self.assertEqual((out["findings"], out["spec"]), ([], None))
        self.assertIn("PROSE-ONLY", log)
        self.assertEqual(fakes.outside_stop_commands(log, "PROSE-ONLY"), [])

    def test_finding_with_no_file_is_an_error_with_the_result_logged(self):
        _, out, log = self.run_in_tmp('```json\n[{"summary": "EXAMPLE-ONLY"}]\n```')
        self.assertTrue((out["error"] or "").startswith("bugs call: unparseable output"), out["error"])
        self.assertEqual(out["findings"], [])
        self.assertIn("EXAMPLE-ONLY", log)


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

    def test_fenced_array_with_one_finding_per_line(self):
        text = ('```json\n[\n{"file": "a.py", "line": 1, "summary": "s1", "severity": "P1"},\n'
                '{"file": "b.py", "line": 2, "summary": "s2", "severity": "P0"}\n]\n```\n')
        self.assertEqual([f["file"] for f in bugs_findings({"result": text}, HEAD)], ["a.py", "b.py"])

    def test_fenced_object_then_fenced_findings_array(self):
        text = ('Each finding looks like:\n```json\n{"file": "x.py", "line": 1}\n```\n'
                '```json\n[{"file": "a.py", "line": 3, "summary": "s", "severity": "P1"}]\n```')
        self.assertEqual([(f["file"], f["line"]) for f in bugs_findings({"result": text}, HEAD)], [("a.py", 3)])

    def test_crlf_fenced_array_over_several_lines(self):
        text = ('Findings:\r\n```json\r\n[\r\n{"file": "a.py", "line": 7, "summary": "s", "severity": "P0"}\r\n]\r\n```'
                '\r\n')
        self.assertEqual([(f["file"], f["line"]) for f in bugs_findings({"result": text}, HEAD)], [("a.py", 7)])

    def test_json_outside_a_json_fence_is_never_a_finding(self):
        for text in ('```text\n[{"file": "x.py", "line": 1, "summary": "example"}]\n```',
                     '[{"file": "a.py", "line": 3, "summary": "s", "severity": "P1"}]',
                     'No findings.\n[]'):
            with self.assertRaises(ValueError, msg=text):
                bugs_findings({"result": text}, HEAD)

    def test_reply_that_does_not_end_with_the_json_block_is_an_error(self):
        block = '```json\n[{"file": "a.py", "line": 5, "summary": "s", "severity": "P0"}]\n```'
        for text in (block + '\nWith no findings the output is:\n```\n[]\n```', block + '\nDone.'):
            with self.assertRaises(ValueError, msg=text):
                bugs_findings({"result": text}, HEAD)

    def test_fence_markers_inside_an_earlier_example_do_not_move_the_block(self):
        text = ('An example:\n~~~text\n```json\n~~~\n'
                '```json\n[{"file": "a.py", "line": 9, "summary": "s", "severity": "P1"}]\n```')
        self.assertEqual([(f["file"], f["line"]) for f in bugs_findings({"result": text}, HEAD)], [("a.py", 9)])

    def test_indented_example_is_never_a_finding(self):
        text = ('The format is:\n\n    ```json\n    [{"file": "x.py", "line": 1,\n      "summary": "example"}]\n    ```\n')
        with self.assertRaises(ValueError):
            bugs_findings({"result": text}, HEAD)

    def test_closing_fence_indented_up_to_three_spaces_is_read(self):
        text = 'Findings:\n```json\n[{"file": "a.py", "line": 2, "summary": "s", "severity": "P0"}]\n  ```\n'
        self.assertEqual([f["file"] for f in bugs_findings({"result": text}, HEAD)], ["a.py"])

    def test_json_lines_inside_a_final_text_block_are_never_findings(self):
        text = ('```text\n```json\nprose\n```json\n[{"file": "x.py", "line": 1, "summary": "example"}]\n```')
        with self.assertRaises(ValueError):
            bugs_findings({"result": text}, HEAD)

    def test_longer_fence_and_info_words_follow_commonmark(self):
        text = ('```json findings\n[{"file": "a.py", "line": 3, "summary": "s", "severity": "P1"}]\n`````')
        self.assertEqual([f["line"] for f in bugs_findings({"result": text}, HEAD)], [3])

    def test_closing_fence_followed_by_a_no_break_space_does_not_close(self):
        with self.assertRaises(ValueError):
            bugs_findings({"result": "```json\n[]\n```\xa0"}, HEAD)

    def test_info_string_is_split_on_spaces_and_tabs_only(self):
        for info in ("\x1cjson", "json\x1c", "\x85json", "\u2003json", "json\xa0"):
            with self.assertRaises(ValueError, msg=repr(info)):
                bugs_findings({"result": f"```{info}\n[]\n```"}, HEAD)
        self.assertEqual(bugs_findings({"result": "``` json\tfindings \n[]\n```"}, HEAD), [])

    def test_nul_and_opener_indent_follow_commonmark(self):
        self.assertEqual(review.final_block(" ```json\n []\n```"), ("json", "[]"))
        text = '```json\n[{"file": "a.py", "line": 1, "summary": "a\x00b", "severity": "P1"}]\n```'
        self.assertEqual([f["summary"] for f in bugs_findings({"result": text}, HEAD)], ["a\ufffdb"])

    def test_list_quote_or_html_with_an_indented_fence_is_an_error(self):
        for text in ('<!--\n```json\n[]\n```', '<div>\n\n```json\n[]\n```', '- item\n  ~~~json\n[]\n~~~',
                     '> q\n```json\n[]\n  ```'):
            with self.assertRaises(ValueError, msg=text):
                bugs_findings({"result": text}, HEAD)

    def test_review_with_a_bullet_list_then_the_block_at_column_0_is_read(self):
        text = ('- **P0** a.py:1 off by one\n> quoted line\n\n```json\n'
                '[{"file": "a.py", "line": 1, "summary": "<b>", "severity": "P0"}]\n```')
        self.assertEqual([f["file"] for f in bugs_findings({"result": text}, HEAD)], ["a.py"])

    def test_finding_without_a_file_is_malformed(self):
        for item in ({"summary": "example"}, {"summary": "s", "file": ""}, {"summary": "s", "file": HEAD + "/"}):
            with self.assertRaises(ValueError, msg=item):
                bugs_findings({"result": f"```json\n{json.dumps([item])}\n```"}, HEAD)

    def test_empty_and_unparseable(self):
        self.assertEqual(bugs_findings({"result": "No findings.\n```json\n[]\n```"}, HEAD), [])
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
