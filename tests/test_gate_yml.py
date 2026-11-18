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
