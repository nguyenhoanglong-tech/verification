# verification

The engine behind the merge gate described in chrislongnguyen/dotfiles `claude/docs/verification/DECISIONS.md`.

A repo opts in with a thin `pull_request_target` caller on its default branch that calls
`.github/workflows/gate.yml` pinned by commit SHA, plus `.github/verification.toml` (see `examples/`).
The caller sets `run-name: verification ${{ github.event.pull_request.head.sha }}` and grants `actions: read`:
under `pull_request_target` a run's own head SHA is the base tip, so the budget read finds each run's records
through the head SHA in its name.
The gate computes the tiers a PR owes from its diff (`engine/tier.py`), runs the owed checks with the
PR head checked out as data, and posts one check run named `verification` from GitHub Actions.

Each gate run writes one verdict record (`engine/verdict.py`) into the `verification` check run's output
text: head and base SHA, tiers, mode, `verdict` (PASS, FAIL or ERROR), the Spec switch, machine check
results, every review finding with its P0 or P1 severity, the Spec table, cost and budget state. The sticky
rule, the budget pace and the dotfiles finding log read that record.

The review (`engine/claude-job`) runs `claude --bare -p` twice at most: `/code-review` on the diff, then the
Spec call when the PR closes an issue whose done-when section existed when the PR opened. The working
directory is the base; the head's files and diff are copied out of it and read as data.

The caller grants `actions: read` (the budget reads the caller's own runs this month), `contents: read`,
`checks: write`, `issues: read` (the Spec switch reads the issues a PR closes), `pull-requests: write` and `id-token: write`. It sets `runner` from the
`VERIFICATION_RUNNER` repo variable and holds one concurrency group per PR with `cancel-in-progress: true`.

Tests: `python3 -m unittest discover -s tests`.

## Self-test a branch

Use this to run the gate from an engine branch before it reaches `dev`. It is for this repo only; real
repos pin the engine by SHA. `pull_request_target` workflows are read from the default branch only, so
the branch is named in a `pull_request` caller committed to a base made for it.

```sh
git push origin my-branch                        # the engine branch to test
selftest/branch.sh start my-branch               # docs-only probe (T0); add --code for a one-line sandbox change (T1)
# prints the PR URL: verify/selftest/my-branch <- selftest-pr/my-branch
gh run list -R nguyenhoanglong-tech/verification --branch selftest-pr/my-branch --workflow selftest-branch.yml
# the gate job log prints: Uses: nguyenhoanglong-tech/verification/.github/workflows/gate.yml@refs/heads/my-branch (<sha>)
selftest/branch.sh stop my-branch                # closes the PR, deletes selftest-pr/my-branch and verify/selftest/my-branch
gh api -X DELETE repos/nguyenhoanglong-tech/verification/git/refs/heads/my-branch   # if it was only for the test; the local pre-push hook refuses unmerged deletes
```

To test more commits, push them to `my-branch` and push any change to `selftest-pr/my-branch`; each new
run reads `gate.yml@my-branch` again. Two branches get two bases, so their runs do not touch each other.

Limits:

- A `pull_request` run cannot mint a Claude token: the federation rule accepts `pull_request_target`
  only (D26). The review ends in `token exchange failed with status 401`, an ERROR, so a branch self-test
  proves tiers, machine checks and the verdict, not the Claude calls. Set `reviews_per_day = 0` on the
  test base to skip the review. Those are proven on
  `verify/attack-base` after the branch lands on `dev`.
- The PR head can edit the caller on its own base, so the attacks that edit workflows (P3, P4c, GATE)
  mean something only on `verify/attack-base`, whose caller sits on `main`.
