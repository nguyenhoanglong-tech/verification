import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Each job's GitHub calls on a private caller repo, and the scope each needs. No job holds checks: write: the
# `verification` check is posted with the gate App's token, never as GitHub Actions (chrislongnguyen/dotfiles#3383).
CALLS = {
    "start": {"contents": "read"},       # git/ref/heads/<base>
    "tier": {"actions": "read",          # actions/workflows/<caller>/runs (budget)
             "checks": "read",           # commits/<sha>/check-runs (budget records)
             "contents": "read",         # contents/.github/verification.toml, compare/base...head
             "issues": "read",           # GraphQL closingIssuesReferences: issue bodies and edits
             "pull-requests": "read"},   # GraphQL pullRequest createdAt
    "head_archive": {"contents": "read"},  # checkout of the head
    "checks": {},                        # runs head code: no token (D13)
    "review": {"actions": "read", "checks": "read",  # budget re-read before the Spec call
               "contents": "read",       # checkout of base and head
               "id-token": "write"},     # OIDC token for the Anthropic exchange
    "gate": {"actions": "read",          # budget records
             "checks": "read",           # check-runs on the head; the POST takes the gate App's token
             "contents": "read"},        # contents/.github/verification.toml (fallback mode)
}


def job_permissions(text: str) -> dict[str, dict[str, str]]:
    jobs, job, in_perms = {}, None, False
    for line in text.split("\n"):
        if m := re.fullmatch(r"  ([A-Za-z_-]+):", line):
            job, in_perms = m.group(1), False
        elif job and (m := re.fullmatch(r"    permissions:\s*(\{\})?", line)):
            jobs[job], in_perms = {}, not m.group(1)
        elif job and in_perms and (m := re.fullmatch(r"      ([a-z-]+): (read|write)(?:\s+#.*)?", line)):
            jobs[job][m.group(1)] = m.group(2)
        elif not line.startswith("      "):
            in_perms = False
    return jobs


class Permissions(unittest.TestCase):
    """Fix 13: on a private caller repo each job holds exactly the scopes its calls need."""

    def test_each_job_holds_exactly_the_scopes_its_calls_need(self):
        self.assertEqual(job_permissions((ROOT / ".github/workflows/gate.yml").read_text()), CALLS)




class StartJob(unittest.TestCase):
    """Fix 1: a fault in the start job (a 5xx on the base ref read) ends the job green; the gate posts the error."""

    def script(self) -> str:
        text = (ROOT / ".github/workflows/gate.yml").read_text()
        start = text.split("\n  start:\n", 1)[1].split("\n  tier:\n", 1)[0]
        body = start.split("python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        return "\n".join(line.removeprefix("          ") for line in body.split("\n"))

    def test_a_base_ref_fault_exits_0_with_no_check_id(self):
        import os
        import sys
        import tempfile
        from unittest import mock
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import fakes
        fake = fakes.GitHub(fail={"GET git/ref/heads/": [fakes.http_error(503)]})
        with tempfile.NamedTemporaryFile("r") as out, fakes.installed(fake, GITHUB_OUTPUT=out.name), \
                mock.patch.object(sys, "path", [str(ROOT / "engine"), *sys.path]):
            code, log = fakes.run(exec, self.script().replace('"engine-src/engine"', repr(str(ROOT / "engine"))), {})
            written = open(out.name).read()
        self.assertEqual(code, 0, log)
        self.assertNotIn("check_id=", written)
        self.assertIn("::error::", log)


def job(text: str, name: str) -> str:
    """One job's block of gate.yml, up to the next job."""
    return re.split(r"\n  [a-z_]+:\n", text.split(f"\n  {name}:\n", 1)[1], 1)[0]


class GateApp(unittest.TestCase):
    """#3383: only the gate App posts `verification`, from the caller's default branch, and an empty key posts nothing."""

    def setUp(self):
        self.gate_yml = (ROOT / ".github/workflows/gate.yml").read_text()
        self.gate = job(self.gate_yml, "gate")

    def test_the_gate_job_takes_the_key_from_the_environment_and_mints_with_a_pinned_action(self):
        self.assertIn("\n    environment: verification-gate\n", self.gate)
        self.assertRegex(self.gate, r"uses: actions/create-github-app-token@[0-9a-f]{40}  # v")
        self.assertIn("permission-checks: write", self.gate)
        self.assertIn("GATE_TOKEN: ${{ steps.app.outputs.token }}", self.gate)

    def test_each_secret_is_read_only_by_jobs_in_its_own_environment(self):
        """dotfiles#3408: the subscription token sits in its own environment, so the review job, which reads PR
        content, can reach no gate App key, and the gate job no token."""
        envs = {"tier": "verification-subscription", "review": "verification-subscription", "gate": "verification-gate"}
        for name in ("start", "tier", "head_archive", "checks", "review", "gate"):
            text = job(self.gate_yml, name)
            self.assertEqual(re.findall(r"\n    environment: ([a-z-]+)", text), [envs[name]] if name in envs else [], name)
            self.assertEqual("secrets.claude_code_oauth_token" in text, name in ("tier", "review"), name)
            self.assertEqual("secrets.VERIFICATION_APP_KEY" in text, name == "gate", name)

    def test_no_check_run_is_written_outside_the_gate_job(self):
        for name in ("start", "tier", "head_archive", "checks", "review"):
            self.assertNotIn("check-runs", job(self.gate_yml, name), name)

    def guard(self, **env) -> int:
        import os
        import subprocess
        script = self.gate.split("KEY: ${{ secrets.VERIFICATION_APP_KEY }}\n        run: |\n", 1)[1].split("\n      - ", 1)[0]
        script = "\n".join(line.removeprefix("          ") for line in script.split("\n"))
        return subprocess.run(["sh", "-c", script], env={"PATH": os.environ["PATH"], **env}, capture_output=True).returncode

    def test_the_guard_fails_closed_before_the_mint(self):
        self.assertLess(self.gate.index("no gate App key"), self.gate.index("create-github-app-token"))
        self.assertEqual(self.guard(GATE_APP_ID="5828645", KEY="k"), 0)
        self.assertEqual(self.guard(GATE_APP_ID="5828645", KEY=""), 1)
        self.assertEqual(self.guard(GATE_APP_ID="", KEY="k"), 1)
        self.assertEqual(self.guard(GATE_APP_ID="5828645; true", KEY="k"), 1)

    def test_the_selftest_caller_passes_the_app_and_its_key_by_name_and_writes_no_check(self):
        caller = (ROOT / ".github/workflows/selftest.yml").read_text()
        self.assertIn("VERIFICATION_APP_KEY: ${{ secrets.VERIFICATION_APP_KEY }}", caller)
        self.assertRegex(caller, r'app_id: "\d+"')
        self.assertNotIn("checks: write", caller)


if __name__ == "__main__":
    unittest.main()
