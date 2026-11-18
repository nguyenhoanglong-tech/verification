import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Each job's GitHub calls on a private caller repo, and the scope each needs. checks: write also reads check runs.
CALLS = {
    "start": {"contents": "read",        # git/ref/heads/<base>
              "checks": "write"},        # POST check-runs (the in-progress check)
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
             "checks": "write",          # check-runs on the head (read) and PATCH/POST the verdict
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


if __name__ == "__main__":
    unittest.main()


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
