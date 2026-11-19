import contextlib
import copy
import io
import json
import os
import re
import signal
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
from urllib.parse import parse_qsl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "attack"))
import suite  # noqa: E402
import tier  # noqa: E402
import verdict  # noqa: E402

APP = 5828607
# Token-shaped test values are joined, so no secret scanner reads this file as holding one.
FAKE_TOKEN = "sk-ant-" + "oat" + "01-" + "A" * 20
API_TOKEN = "sk-ant-" + "api03-" + "Zq7" * 14
FRAGMENT = "Xy9" + "Kw4Lm" * 9  # a token's tail without its prefix: mixed case and digits, 48 characters
SHORT = "Ab3" + "Xy9Kw4Lm2"  # a short prefix-less fragment that no shape rule can tell from a word
CANARY = "P7 token found: length 108"
TOML = """# top
reviews_per_day = 5  # api pace
budget_month_usd = 100

[subscription]
fallback = true
reviews_per_day = 3
"""
COLUMNS = "pr\tcheck_run\thead_sha\tverdict\tcall\tseverity\tfile\tline\tsummary"
PROBE_SHA, BASE_SHA, TIP, MOVED, ATTACK_SHA, FORK_SHA = "p" * 40, "b" * 40, "m" * 40, "q" * 40, "a" * 40, "f" * 40
POLICY = ("X Pull request o/r#5 is not mergeable: the base branch policy prohibits the merge.\n"
          "To have the pull request merged after all the requirements have been met, add the `--auto` flag.")


def gate_record(**over):
    record = {"schema": 1, "head_sha": PROBE_SHA, "base_sha": BASE_SHA, "tier": "T1", "mode": "shadow", "verdict": "PASS",
              "title": "T1 passed", "switch_spec": False, "machine": [], "findings": [], "spec": None, "cost_usd": 0,
              "billing": "subscription", "refused": None, "subscription_cost_usd": 0.1, "budget": {}, "error": None,
              "run_id": 99, "run_attempt": 1}
    return {**record, **over}


class FakeClock:
    """suite's clock: sleep only moves it, so a deadline arrives at once; the ref stamp is fixed."""

    gmtime = staticmethod(time.gmtime)

    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def strftime(self, fmt, *a):
        return "1119220000" if fmt in ("%m%d%H%M%S", "%m%d%H%M") else time.strftime(fmt, *a)


class FakeGitHub:
    """The gh CLI over an in-memory GitHub: refs, contents, PRs (forks too), merges, check runs with filter, pages and
    annotations, PR comments and reviews, Actions runs, attempts, jobs with the API's own count, and logs. Every call
    the suite makes goes through gh, so the stub stands at the same edge for the old code and the new."""

    def __init__(self):
        self.refs = {"master": TIP, "main": TIP, "verify/attack-base": TIP}
        self.prs, self.checks, self.runs, self.attempts, self.logs, self.annotations = {}, [], {}, {}, {}, {}
        self.comments = {"issues": [], "pulls": [], "reviews": []}
        self.fail, self.calls, self.hooks, self.writes, self.merges = {}, [], [], [], []
        self.moved, self.pr_commits, self.findings_read, self.merge_answer = False, None, None, (1, POLICY)

    def check(self, name, head=PROBE_SHA, status="completed", app=APP, text=None, summary="", conclusion="success"):
        self.checks.append({"id": len(self.checks) + 1, "name": name, "status": status,
                            "conclusion": conclusion if status == "completed" else None, "head_sha": head,
                            "app": {"id": app}, "html_url": "u",
                            "output": {"title": "T1 passed", "summary": summary, "text": text}})
        return self.checks[-1]

    def run(self, run_id, attempts=1, status="completed", jobs=None, logs=None, total=None):
        """An Actions run on the probe commit; its jobs default to one review job per attempt."""
        self.runs[run_id] = {"id": run_id, "head_sha": BASE_SHA, "display_title": f"verification {PROBE_SHA}",
                             "head_branch": "PROBE-HEAD", "status": status, "run_attempt": attempts}
        for a in range(1, attempts + 1):
            job = run_id * 10 + a
            self.attempts[(run_id, a)] = {"status": status, "total": total, "jobs": [
                {"id": job, "name": "verification / review", "conclusion": "success"}] if jobs is None else jobs}
            self.logs.setdefault(job, [(0, "review ran\n")])
        for job_id, answers in (logs or {}).items():
            self.logs[job_id] = answers

    def gate(self, run_id, attempt=1, head=PROBE_SHA, conclusion="success", **record):
        """The gate App's check for one attempt of a run, and the run itself."""
        if run_id not in self.runs:
            self.run(run_id, attempt)
        if self.runs[run_id]["run_attempt"] < attempt:
            self.runs[run_id]["run_attempt"] = attempt
            self.attempts[(run_id, attempt)] = {"status": "completed", "total": None, "jobs": [
                {"id": run_id * 10 + attempt, "name": "verification / review", "conclusion": "success"}]}
            self.logs.setdefault(run_id * 10 + attempt, [(0, "review ran\n")])
        return self.check("verification", head=head, conclusion=conclusion,
                          text=verdict.render_text(gate_record(head_sha=head, run_id=run_id, run_attempt=attempt, **record)))

    def gh(self, *args, input=None, check=True):
        self.calls.append(args)
        out, rc = self.answer(args)
        for when, then in list(self.hooks):
            if when(args):
                then()
        if check and rc:
            raise RuntimeError(f"gh {' '.join(args[:3])}: {out}")
        return SimpleNamespace(stdout=out if rc == 0 or "--include" in args else "", stderr=out, returncode=rc)

    def failing(self, key):
        if self.fail.get(key, 0) > 0:
            self.fail[key] -= 1
            return True
        return False

    def page(self, items, q):
        size, n = int(q.get("per_page", 30)), int(q.get("page", 1))
        return items[(n - 1) * size:n * size]

    def head_of(self, pr):
        p = self.prs[pr]
        return p.get("sha") or (MOVED if self.moved else self.refs.get(p["head"], PROBE_SHA))

    def answer(self, args):
        if args[0] == "pr":
            return self.pr(args)
        method, fields, path, i = "GET", {}, None, 1
        while i < len(args):
            if args[i] == "-X":
                method, i = args[i + 1], i + 2
            elif args[i] in ("-f", "-H"):
                if args[i] == "-f":
                    k, v = args[i + 1].split("=", 1)
                    fields[k] = v
                i += 2
            elif args[i] == "--include":
                i += 1
            else:
                path, i = args[i], i + 1
        path, _, query = path.partition("?")
        q, tail = dict(parse_qsl(query)), "/".join(path.split("/")[3:])
        ok = lambda body: (json.dumps(body), 0)  # noqa: E731
        if tail.endswith(".github/workflows/verification.yml"):
            return 'app_id: "5828607"', 0
        if tail.endswith(".github/verification.toml") and "-H" in args:
            return TOML, 0
        if tail.startswith("contents/"):
            if method != "PUT":
                return '{"message": "Not Found"}', 1
            if self.failing("put"):
                return '{"message": "write refused"}', 1
            self.writes.append((fields["branch"], tail))
            sha = PROBE_SHA if tail.endswith("probe.py") else BASE_SHA if tail.endswith(".toml") else \
                ATTACK_SHA if self.refs.get(fields["branch"]) != ATTACK_SHA else "c" * 40
            self.refs[fields["branch"]] = sha
            return ok({})
        if tail.startswith("branches/"):
            name = tail[len("branches/"):]
            return ok({"commit": {"sha": self.refs[name]}}) if name in self.refs else ('{"message": "Not Found"}', 1)
        if tail == "git/refs" and method == "POST":
            name = fields["ref"][len("refs/heads/"):]
            if name in self.refs:
                return '{"message": "Reference already exists"}', 1
            self.refs[name] = fields["sha"]
            return ok({})
        if tail.startswith("git/refs/heads/") and method == "DELETE":
            name = tail[len("git/refs/heads/"):]
            if self.failing("delete") or name not in self.refs:
                return '{"message": "failed"}', 1
            del self.refs[name]
            return "", 0
        if tail.startswith("git/ref/heads/"):
            name = tail[len("git/ref/heads/"):]
            if name in self.refs:
                return "HTTP/2.0 200 OK\n\n" + json.dumps({"object": {"sha": self.refs[name]}}), 0
            return "HTTP/2.0 404 Not Found\n\n{}", 1
        m = re.fullmatch(r"commits/(\w+)/check-runs", tail)
        if m:
            found = [c for c in reversed(self.checks) if c["head_sha"] == m.group(1)]  # newest first
            if q.get("filter", "latest") == "latest":
                found = list({(c["name"], c["app"]["id"]): c for c in reversed(found)}.values())[::-1]
            return ok({"total_count": len(found), "check_runs": self.page(found, q)})
        if re.fullmatch(r"commits/\w+/statuses", tail):
            return ok([])
        m = re.fullmatch(r"check-runs/(\d+)/annotations", tail)
        if m:
            return ok(self.page(self.annotations.get(int(m.group(1)), []), q))
        m = re.fullmatch(r"(issues|pulls)/(\d+)/(comments|reviews|commits)", tail)
        if m:
            if m.group(3) == "commits":
                return ok(self.page([{"sha": s} for s in (self.pr_commits or [self.head_of(int(m.group(2)))])], q))
            kind = "issues" if m.group(1) == "issues" else "pulls" if m.group(3) == "comments" else "reviews"
            return ok(self.page(self.comments[kind], q))
        if tail == "actions/runs":
            runs = [r for r in self.runs.values() if r["head_sha"] == q.get("head_sha")
                    or "branch" in q and r["head_branch"] == "PROBE-HEAD" and q["branch"] == self.probe_head()]
            return ok({"total_count": len(runs), "workflow_runs": self.page(runs, q)})
        m = re.fullmatch(r"actions/runs/(\d+)(?:/attempts/(\d+)(/jobs)?)?", tail)
        if m:
            run_id = int(m.group(1))
            if not m.group(2):
                return ok(self.runs[run_id])
            attempt = self.attempts[(run_id, int(m.group(2)))]
            if m.group(3):
                total = len(attempt["jobs"]) if attempt["total"] is None else attempt["total"]
                return ok({"total_count": total, "jobs": self.page(attempt["jobs"], q)})
            return ok({"status": attempt["status"]})
        m = re.fullmatch(r"actions/jobs/(\d+)/logs", tail)
        if m:
            answers = self.logs[int(m.group(1))]
            rc, text = answers.pop(0) if len(answers) > 1 else answers[0]
            return text, rc
        raise AssertionError(f"unexpected gh call {args}")

    def probe_head(self):
        return next((p["head"] for p in self.prs.values() if not p.get("cross")), None)

    def pr(self, args):
        if args[1] == "create":
            n = max([4, *self.prs]) + 1
            self.prs[n] = {"head": args[args.index("--head") + 1], "base": args[args.index("--base") + 1], "state": "OPEN"}
            return f"https://github.com/o/r/pull/{n}\n", 0
        if args[1] == "list":
            head = args[args.index("--head") + 1]
            mine = [n for n, p in self.prs.items() if p["head"] == head and p["state"] == "OPEN"]
            if "-q" in args:
                return "".join(f"{n}\n" for n in mine), 0
            return json.dumps([{"number": n, "headRefOid": self.head_of(n), "isCrossRepository": bool(self.prs[n].get("cross"))}
                               for n in mine]), 0
        n = int(args[2])
        p = self.prs[n]
        if args[1] == "close":
            if self.failing("close"):
                return "failed", 1
            p["state"] = "CLOSED"
            if "--delete-branch" in args:
                self.refs.pop(p["head"], None)
            return "", 0
        if args[1] == "merge":
            self.merges.append(args)
            rc, text = self.merge_answer
            if rc == 0:
                p["state"] = "MERGED"
            return text, rc
        if "-q" in args:
            return p["state"] + "\n", 0
        return json.dumps({"number": n, "url": "u", "state": p["state"], "mergeStateStatus": "BLOCKED",
                           "headRefOid": self.head_of(n), "mergedAt": None, "baseRefName": p["base"],
                           "isCrossRepository": bool(p.get("cross"))}), 0


def subprocess_stub(fake, raises=None):
    """git rev-parse reads master's tip; the finding log reports the gate checks it read on the probe commit."""
    def sub(cmd, **_):
        if cmd[0] == "git":
            return SimpleNamespace(stdout=TIP + "\n", stderr="", returncode=0)
        if raises:
            raise raises
        read = fake.findings_read
        if read is None:
            read = sum(c["name"] == "verification" and c["app"]["id"] == APP and c["head_sha"] == PROBE_SHA
                       for c in fake.checks)
        return SimpleNamespace(stdout=COLUMNS + "\n", returncode=0,
                               stderr=f"read {read} verification check runs on 1 PRs: 0 findings, 0 non-PASS run rows, "
                                      "0 with no record block\n")
    return sub


def run_p7(fake, raises=None):
    """run_p7 against the fake: (record, saved P7.json text)."""
    with tempfile.TemporaryDirectory() as out, mock.patch.object(suite, "gh", fake.gh), \
            mock.patch.object(suite, "time", FakeClock()), \
            mock.patch.object(suite.subprocess, "run", subprocess_stub(fake, raises)):
        rec = suite.run_p7("/dotfiles", Path(out))
        return rec, (Path(out) / "P7.json").read_text()


def p7_cli(fake, raises=None):
    """`suite.py p7` against the fake: (exit code, stdout, saved P7.json text)."""
    stdout = io.StringIO()
    with tempfile.TemporaryDirectory() as out, mock.patch.object(suite, "gh", fake.gh), \
            mock.patch.object(suite, "time", FakeClock()), \
            mock.patch.object(suite.subprocess, "run", subprocess_stub(fake, raises)), \
            mock.patch.object(sys, "argv", ["suite.py", "p7", "--dotfiles", "/dotfiles", "--out", out]), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
        with unittest.TestCase().assertRaises(SystemExit) as stop:
            suite.main()
        return stop.exception.code, stdout.getvalue(), (Path(out) / "P7.json").read_text()


def stamp_names():
    stamp = f"1119220000-{os.getpid()}"
    return f"verify/selftest/p7-{stamp}", f"verify/selftest/p7-{stamp}-head"


def gh_is(*prefix):
    return lambda args: args[:len(prefix)] == prefix


def nth(when, n):
    """A hook predicate that fires on the nth call it matches, and only then."""
    seen = []

    def pred(args):
        if when(args):
            seen.append(1)
            return len(seen) == n
        return False
    return pred


def deliver_sigterm():
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)  # interrupted as soon as the signal is delivered


def outcome(rec):
    """The label `suite.py p7` prints for a record: an error reason is ERROR, a leak FAILED."""
    held, why = suite.judge(rec)
    return "HELD" if held else "ERROR" if why.startswith("error:") else "FAILED"


class P7Case(unittest.TestCase):
    def setUp(self):  # a run that escapes run_p7 must not leave its handlers to the next test
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.addCleanup(signal.signal, sig, signal.getsignal(sig))
        self.fake = FakeGitHub()

    def assert_torn_down(self, rec):
        self.assertEqual({p["state"] for p in self.fake.prs.values() if not p.get("cross")}, {"CLOSED"})
        self.assertEqual(set(self.fake.refs), {"master", "main", "verify/attack-base"})
        self.assertEqual(set(rec["gone"]["refs"].values()), {404})


class C1Evidence(P7Case):
    """C1: HELD only from a complete, positive evidence set bound to the probe commit; anything else is ERROR."""

    def test_c1_a_partial_jobs_list_is_an_error(self):
        self.fake.run(99, total=2)  # the API counts two jobs; the list holds one
        self.fake.gate(99)
        rec, _ = run_p7(self.fake)
        self.assertEqual(outcome(rec), "ERROR")

    def test_c1_a_check_starting_after_the_last_settle_is_seen(self):
        self.fake.gate(99)
        late = {}

        def start():
            late["c"] = self.fake.check("verification / review", app=suite.ACTIONS_APP, status="queued")
        polls = []

        def finish():
            polls.append(1)
            if "c" in late and len(polls) == 3:
                late["c"].update(status="completed", conclusion="success")
                late["c"]["output"]["summary"] = CANARY
        view = lambda a: a[:2] == ("pr", "view") and "-q" not in a and "headRefOid" in ",".join(a)  # noqa: E731
        self.fake.hooks += [(nth(view, 2), start), (lambda a: "/check-runs" in a[1] and "annotations" not in a[1], finish)]
        rec, _ = run_p7(self.fake)
        self.assertNotEqual(outcome(rec), "HELD")

    def test_c1_the_finding_log_is_bound_to_the_probe_commit(self):
        for name, mutate in (("the PR has another commit", lambda f: setattr(f, "pr_commits", [PROBE_SHA, MOVED])),
                             ("the log counted other checks", lambda f: setattr(f, "findings_read", 3))):
            with self.subTest(name):
                self.fake = FakeGitHub()
                self.fake.gate(99)
                mutate(self.fake)
                rec, _ = run_p7(self.fake)
                self.assertEqual(outcome(rec), "ERROR")

    def test_c1_missing_evidence_prints_error(self):
        self.fake.gate(99, billing="api")
        code, stdout, _ = p7_cli(self.fake)
        self.assertEqual(code, 1)
        self.assertRegex(stdout, r"^P7\s+ERROR\b")


def attack(fake, name, hooks=()):
    """run_attack for one attack against the fake engine repo: (record, outcome)."""
    fake.hooks += list(hooks)
    with mock.patch.object(suite, "gh", fake.gh), mock.patch.object(suite, "time", FakeClock()):
        rec = suite.run_attack("o/r", "verify/attack-base", name, suite.ATTACKS[name], "1119", 5828645)
    held, why = suite.judge(rec)
    return rec, ("HELD" if held else "ERROR" if why.startswith("error:") or rec.get("error") else "FAILED")


ON_WAIT = lambda a: a[0] == "api" and "check-runs?per_page=100" in a[1]  # noqa: E731  wait_verification's read


class C2Attacks(unittest.TestCase):
    """C2: every attack waits on and scores its staged commit; a refusal is HELD only when it is the gate's."""

    def engine(self, conclusion="failure"):
        fake = FakeGitHub()
        fake.check("verification", head=ATTACK_SHA, app=5828645, conclusion=conclusion)
        return fake

    def test_c2_a_gate_refusal_holds(self):
        _, result = attack(self.engine(), "P2")
        self.assertEqual(result, "HELD")

    def test_c2_a_moved_head_is_an_error(self):
        fake = self.engine()
        fake.check("verification", head=MOVED, app=5828645, conclusion="failure")
        _, result = attack(fake, "P2", [(ON_WAIT, lambda: setattr(fake, "moved", True))])
        self.assertEqual(result, "ERROR")

    def test_c2_an_auth_failed_merge_is_an_error(self):
        fake = self.engine()
        fake.merge_answer = (1, "HTTP 401: Bad credentials (https://api.github.com/graphql)")
        _, result = attack(fake, "P2")
        self.assertEqual(result, "ERROR")


class C3Credentials(P7Case):
    """C3: no credential byte is saved or printed; leak detection covers annotations and PR comments."""

    def test_c3_a_short_fragment_in_a_job_name_or_an_error_is_never_saved_or_printed(self):
        self.fake.run(99, jobs=[{"id": 991, "name": "verification / review", "conclusion": "success"},
                                {"id": 992, "name": f"build {SHORT}", "conclusion": "success"}],
                      logs={992: [(0, "build ran\n")]})
        self.fake.gate(99)
        _, stdout, saved = p7_cli(self.fake, raises=RuntimeError(f"finding log failed near {SHORT}"))
        self.assertNotIn(SHORT, saved)
        self.assertNotIn(SHORT, stdout)

    def test_c3_annotations_and_pr_comments_are_scanned(self):
        for where in ("annotation", "issues", "pulls", "reviews"):
            with self.subTest(where):
                self.fake = FakeGitHub()
                gate = self.fake.gate(99)
                if where == "annotation":
                    self.fake.annotations[gate["id"]] = [{"message": CANARY, "path": "verify-p7/probe.py"}]
                else:
                    self.fake.comments[where] = [{"body": CANARY}]
                rec, _ = run_p7(self.fake)
                held, why = suite.judge(rec)
                self.assertFalse(held)
                self.assertIn("leak", why)

    def test_c3_scrub_covers_dict_keys(self):
        self.assertNotIn(API_TOKEN, json.dumps(suite.scrub({API_TOKEN: FRAGMENT})))


class C4Teardown(P7Case):
    """C4: teardown and merge touch only what the suite made."""

    def test_c4_a_fork_pr_with_the_same_head_name_is_never_closed(self):
        _, head = stamp_names()
        self.fake.prs[6] = {"head": head, "base": "verify/selftest/x", "state": "OPEN", "cross": True, "sha": FORK_SHA}
        self.fake.gate(99)
        self.fake.hooks.append((gh_is("pr", "create"), deliver_sigterm))
        rec, _ = run_p7(self.fake)
        self.assertEqual(self.fake.prs[6]["state"], "OPEN")
        self.assertEqual([p["state"] for p in self.fake.prs.values() if not p.get("cross")], ["CLOSED"])

    def test_c4_a_ref_someone_moved_is_never_deleted(self):
        _, head = stamp_names()
        self.fake.gate(99)
        self.fake.hooks.append((gh_is("pr", "create"), lambda: self.fake.refs.__setitem__(head, FORK_SHA)))
        rec, _ = run_p7(self.fake)
        self.assertEqual(self.fake.refs.get(head), FORK_SHA)
        self.assertNotEqual(outcome(rec), "HELD")

    def test_c4_a_retargeted_pr_is_never_merged(self):
        fake = FakeGitHub()
        fake.check("verification", head=ATTACK_SHA, app=5828645)
        fake.merge_answer = (0, "merged")
        _, result = attack(fake, "P1", [(ON_WAIT, lambda: fake.prs[5].update(base="main"))])
        self.assertEqual(fake.merges, [])
        self.assertEqual(result, "ERROR")


class RunP7(P7Case):
    """Earlier rounds' cases, on the derived evidence."""

    def test_clean_run_holds(self):
        self.fake.gate(99)
        rec, saved = run_p7(self.fake)
        self.assertEqual(suite.judge(rec), (True, "held"))
        self.assertEqual(suite.judge(json.loads(saved)), (True, "held"))
        self.assert_torn_down(rec)

    def test_the_cli_prints_held(self):
        self.fake.gate(99)
        code, stdout, _ = p7_cli(self.fake)
        self.assertEqual(code, 0)
        self.assertRegex(stdout, r"^P7\s+HELD\b")

    def test_the_saved_record_holds_no_text_read_from_github(self):
        self.fake.gate(99)
        self.fake.logs[991] = [(0, f"review ran\n{API_TOKEN}\n{FRAGMENT}\nverification / review\n")]
        rec, saved = run_p7(self.fake)
        for text in (API_TOKEN, API_TOKEN[len("sk-ant-api03-"):], FRAGMENT, "review ran", "verification / review"):
            self.assertNotIn(text, saved)
        self.assertIn("leak", suite.judge(json.loads(saved))[1])

    def test_a_gate_run_or_re_run_posted_while_logs_are_read_is_read_too(self):
        for late in ((100, 1), (99, 2)):
            with self.subTest(late=late):
                self.fake = FakeGitHub()
                self.fake.gate(99)
                self.fake.hooks.append((lambda a: a[1].endswith("/actions/jobs/991/logs"), lambda: self.fake.gate(*late)))
                rec, _ = run_p7(self.fake)
                self.assertIn("%d/%d" % late, rec["attempts"])
                self.assertEqual(sum(c["gate"] for c in rec["checks"]), 2)
                self.assertEqual(suite.judge(rec), (True, "held"))

    def test_leaks_anywhere_on_the_probe_fail(self):
        cases = {
            "an attempt with no gate record": lambda f: (f.run(99, attempts=2, logs={991: [(0, FAKE_TOKEN)]}), f.gate(99, 2)),
            "a run whose gate never posted": lambda f: (f.gate(99), f.run(98, logs={981: [(0, FAKE_TOKEN)]})),
            "a check run past the first page": lambda f: (
                f.check("verification / review", app=suite.ACTIONS_APP, summary=FAKE_TOKEN),
                [f.check(f"other {n}", app=suite.ACTIONS_APP) for n in range(99)], f.gate(99)),
            "an sk-ant-api03 value": lambda f: (f.gate(99), f.logs.__setitem__(991, [(0, API_TOKEN)])),
        }
        for name, stage in cases.items():
            with self.subTest(name):
                self.fake = FakeGitHub()
                stage(self.fake)
                rec, _ = run_p7(self.fake)
                held, why = suite.judge(rec)
                self.assertEqual((held, why.split(":")[0]), (False, "leak"))

    def test_gaps_are_errors(self):
        def busy_forever(f):
            f.gate(99)
            f.check("verification / review", app=suite.ACTIONS_APP, status="in_progress")

        cases = {
            "an older gate check billed the API": lambda f: (f.gate(99, 1, billing="api"), f.gate(99, 2)),
            "a settle deadline": busy_forever,
            "a blank log": lambda f: (f.run(99, jobs=[{"id": 991, "name": "verification / review", "conclusion": "success"},
                                                      {"id": 992, "name": "verification / tier", "conclusion": "success"}],
                                            logs={992: [(0, "")]}), f.gate(99)),
            "an attempt with no jobs": lambda f: (f.gate(99), f.run(98, jobs=[])),
            "a moved head": lambda f: (f.gate(99), f.gate(100, head=MOVED), setattr(f, "moved", True)),
            "a name collision": lambda f: f.refs.__setitem__(stamp_names()[0], "e" * 40),
            "a teardown that keeps failing": lambda f: (f.gate(99), f.fail.update(delete=99)),
        }
        for name, stage in cases.items():
            with self.subTest(name):
                self.fake = FakeGitHub()
                stage(self.fake)
                with contextlib.redirect_stderr(io.StringIO()):
                    rec, _ = run_p7(self.fake)
                self.assertEqual(outcome(rec), "ERROR")

    def test_a_name_collision_never_deletes_the_existing_ref(self):
        base, _ = stamp_names()
        self.fake.refs[base] = "e" * 40
        run_p7(self.fake)
        self.assertEqual(self.fake.refs.get(base), "e" * 40)

    def test_a_busy_workflow_on_the_probe_commit_is_waited_for(self):
        self.fake.gate(99)
        self.fake.run(98, status="in_progress", logs={981: [(0, "review ran\n" + FAKE_TOKEN)]})
        polls = []

        def finish():
            polls.append(1)
            if len(polls) == 3:
                self.fake.runs[98]["status"] = self.fake.attempts[(98, 1)]["status"] = "completed"
        self.fake.hooks.append((lambda a: "/check-runs" in a[1], finish))
        rec, _ = run_p7(self.fake)
        self.assertIn("leak", suite.judge(rec)[1])

    def test_a_stop_right_after_pr_create_still_closes_the_pr(self):
        self.fake.gate(99)
        self.fake.hooks.append((gh_is("pr", "create"), deliver_sigterm))
        rec, _ = run_p7(self.fake)
        self.assertEqual(rec["error"]["code"], "stopped")
        self.assert_torn_down(rec)

    def test_a_failed_close_or_delete_is_retried(self):
        self.fake.gate(99)
        self.fake.fail = {"close": 1, "delete": 2}
        rec, _ = run_p7(self.fake)
        self.assert_torn_down(rec)
        self.assertEqual(suite.judge(rec), (True, "held"))

    def test_sigterm_mid_run_still_tears_down(self):
        self.fake.gate(99)
        self.fake.hooks.append((lambda a: "/check-runs" in a[1], deliver_sigterm))
        rec, saved = run_p7(self.fake)
        self.assertEqual(rec["error"]["code"], "stopped")
        self.assert_torn_down(rec)
        self.assertFalse(suite.judge(json.loads(saved))[0])

    def test_a_stop_after_staging_does_not_cut_teardown(self):
        # Calling the installed handler models a signal delivered at the top of finally, before teardown starts.
        self.fake.gate(99)
        self.fake.hooks.append((gh_is("pr", "close"), lambda: signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)))
        rec, _ = run_p7(self.fake)
        self.assert_torn_down(rec)

    def test_failure_before_the_head_deletes_only_the_base(self):
        self.fake.fail = {"put": 1}
        rec, _ = run_p7(self.fake)
        self.assertEqual(rec["error"]["code"], "exception")
        deleted = [c[3].rsplit("/heads/", 1)[1] for c in self.fake.calls if c[:3] == ("api", "-X", "DELETE")]
        self.assertEqual(deleted, [rec["base"]])
        self.assertEqual(set(self.fake.refs), {"master", "main", "verify/attack-base"})


class Judge(P7Case):
    """The judge on a held record with one derived field broken: every gap is an error."""

    def test_each_gap_in_a_held_record_is_an_error(self):
        self.fake.gate(99)
        held, _ = run_p7(self.fake)
        self.assertEqual(suite.judge(held), (True, "held"))
        gate = next(c for c in held["checks"] if c["gate"])["record"]
        cases = {
            "billed the API": lambda r: r["checks"][0]["record"].update(subscription=False),
            "review error": lambda r: r["checks"][0]["record"].update(error=True),
            "skipped for budget": lambda r: r["checks"][0]["record"].update(skipped=True),
            "trimmed": lambda r: r["checks"][0]["record"].update(trimmed=True),
            "not T1": lambda r: r["checks"][0]["record"].update(t1=False),
            "no gate record": lambda r: r["checks"][0].update(record=None),
            "an unread scan": lambda r: r["scans"]["pr comments"].update(read=False),
            "a missing scan": lambda r: r["scans"].pop("pr reviews"),
            "a partial attempt": lambda r: r["attempts"][f"{gate['run_id']}/1"].update(total_count=2),
            "a run off the probe": lambda r: r["runs"][0].update(on_probe=False),
            "a check still going": lambda r: r["checks"][0].update(status="in_progress"),
            "another PR head": lambda r: r.update(pr_head=MOVED),
            "finding log count": lambda r: r["finding_log"].update(read=2),
            "finding log rows": lambda r: r["finding_log"].update(rows_on_probe=False),
            "finding log PR": lambda r: r["finding_log"].update(pr_is_probe=False),
            "PR open": lambda r: r["gone"].update(pr_state="OPEN"),
            "ref still there": lambda r: r["gone"]["refs"].update({r["head"]: 200}),
            "teardown failed": lambda r: r.update(teardown_failed=["delete x"]),
            "run error": lambda r: r.update(error={"code": "exception"}),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                rec = copy.deepcopy(held)
                mutate(rec)
                held_, why = suite.judge(rec)
                self.assertEqual(suite.label(held_, why), "ERROR", why)

    def test_a_leak_is_failed_even_in_a_run_that_errored(self):
        self.fake.gate(99)
        rec, _ = run_p7(self.fake)
        rec["error"] = {"code": "unsettled"}
        rec["scans"]["job 991 log"]["leak"] = True
        held, why = suite.judge(rec)
        self.assertEqual(suite.label(held, why), "FAILED")


class Wait(unittest.TestCase):
    def test_wait_verification_reports_its_deadline(self):
        fake = FakeGitHub()
        with mock.patch.object(suite, "gh", fake.gh), mock.patch.object(suite, "time", FakeClock()):
            self.assertIs(suite.wait_verification("o/r", PROBE_SHA, APP), False)
            fake.gate(99)
            self.assertIs(suite.wait_verification("o/r", PROBE_SHA, APP), True)


class Logs(unittest.TestCase):
    def test_a_log_not_yet_archived_is_fetched_again(self):
        fake = FakeGitHub()
        fake.logs[5] = [(1, '{"message":"Not Found"}'), (0, ""), (0, "review ran\n")]
        with mock.patch.object(suite, "gh", fake.gh), mock.patch.object(suite, "time", FakeClock()):
            self.assertEqual(suite.fetch_log("o/r", 5), "review ran\n")


class Scope(unittest.TestCase):
    def test_writes_outside_the_scope_are_refused(self):
        fake = FakeGitHub()
        for ref in ("main", "dev", "master", "feature/x", "verify/attack-p1-1", "selftest-pr/p7-1"):
            with self.subTest(ref=ref), mock.patch.object(suite, "gh", fake.gh):
                with self.assertRaises(Exception):
                    suite.write_files("o/r", ref, {"a.txt": "b"})
        self.assertEqual(fake.writes, [])

    def test_run_refuses_a_base_outside_the_scope(self):
        fake = FakeGitHub()
        with tempfile.TemporaryDirectory() as out, mock.patch.object(suite, "gh", fake.gh), \
                mock.patch.object(suite, "time", FakeClock()), \
                mock.patch.object(sys, "argv", ["suite.py", "run", "--repo", "o/r", "--app", "1", "--base", "main",
                                                "--only", "P1", "--out", out]):
            with self.assertRaises(SystemExit):
                suite.main()
        self.assertEqual([c for c in fake.calls if "POST" in c or "PUT" in c], [])

    def test_the_scope(self):
        for ref in ("verify/attack-base", "verify/attack-base-p7-1119", "verify/attack-base-1119-p1",
                    "verify/selftest/p7-1", "verify/selftest/p7-1-head"):
            self.assertEqual(suite.in_scope(ref), ref)
        for ref in ("main", "dev", "verify/attack-basement", "verify/selftest", "x/verify/selftest/a"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                suite.in_scope(ref)


class Toml(unittest.TestCase):
    def test_top_level_only(self):
        import tomllib
        conf = tomllib.loads(suite.p7_toml(TOML))
        self.assertEqual(conf["reviews_per_day"], 0)
        self.assertEqual(conf["subscription"]["reviews_per_day"], 3)
        self.assertIn("# api pace", suite.p7_toml(TOML))

    def test_refuses_without_fallback(self):
        with self.assertRaises(ValueError):
            suite.p7_toml(TOML.replace("fallback = true", "fallback = false"))

    def test_refuses_without_top_level_key(self):
        with self.assertRaises(ValueError):
            suite.p7_toml(TOML.replace("reviews_per_day = 5  # api pace\n", ""))


class Probe(unittest.TestCase):
    def test_probe_is_t1(self):
        import tomllib
        rules = tomllib.loads((ROOT / "examples/dotfiles.verification.toml").read_text())["tiers"]
        lines = len(suite.PROBE.splitlines())
        result = tier.classify([{"filename": "verify-p7/probe.py", "additions": lines, "deletions": 0}], rules)
        self.assertEqual(result.tiers, ["T1"])

    def test_the_probe_asks_for_no_token_character(self):
        self.assertNotIn("sk-ant-" + "oat", suite.PROBE)
        self.assertIsNone(re.search(r"first \d+ characters", suite.PROBE))
        self.assertIn("Never write any value you read", suite.PROBE)
        self.assertIn("P7 token found: length <n>", suite.PROBE)
        self.assertFalse(suite.leaked(suite.PROBE), "the probe quoted in a log must not read as a leak")


if __name__ == "__main__":
    unittest.main()
