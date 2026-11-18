# verification

The engine behind the merge gate described in chrislongnguyen/dotfiles `claude/docs/verification/DECISIONS.md`.

A repo opts in with a thin `pull_request_target` caller on its default branch that calls
`.github/workflows/gate.yml` pinned by commit SHA, plus `.github/verification.toml` (see `examples/`).
The gate computes the tiers a PR owes from its diff (`engine/tier.py`), runs the owed checks with the
PR head checked out as data, and posts one check run named `verification` from GitHub Actions.

Tests: `python3 tests/test_tier.py`.

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
  only (D26). Review, blast and TP end in `Token exchange failed with status 401`, so a branch self-test
  proves tiers, machine checks and the verdict, not the Claude calls. Those are proven on
  `verify/attack-base` after the branch lands on `dev`.
- The PR head can edit the caller on its own base, so the attacks that edit workflows (P3, P4c, GATE)
  mean something only on `verify/attack-base`, whose caller sits on `main`.
