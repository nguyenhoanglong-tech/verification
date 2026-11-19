# verification

The engine behind the merge gate described in chrislongnguyen/dotfiles `claude/docs/verification/DECISIONS.md`.

A repo opts in with a thin `pull_request_target` caller on its default branch that calls
`.github/workflows/gate.yml` pinned by commit SHA, plus `.github/verification.toml` (see `examples/`).
The caller sets `run-name: verification ${{ github.event.pull_request.head.sha }}` and grants `actions: read`:
under `pull_request_target` a run's own head SHA is the base tip, so the budget read finds each run's records
through the head SHA in its name.
The gate computes the tiers a PR owes from its diff (`engine/tier.py`), runs the owed checks with the
PR head checked out as data, and posts one check run named `verification` as the caller's gate App.
Every workflow runs as GitHub Actions, a PR's own included, so a `verification` check from GitHub Actions
proves nothing; the ruleset requires the gate App's (chrislongnguyen/dotfiles#3383).

Each gate run writes one verdict record (`engine/verdict.py`) into the `verification` check run's output
text: head and base SHA, tiers, mode, `verdict` (PASS, FAIL or ERROR), the Spec switch, machine check
results, every review finding with its P0 or P1 severity, the Spec table, cost and budget state. The sticky
rule, the budget pace and the dotfiles finding log read that record.

The review (`engine/claude-job`) makes two calls at most: `/code-review` on the diff, then the Spec call when
the PR closes an issue whose done-when section existed when the PR opened. The head's files and diff are
copied out of the working directory and read as data.

Each call is billed to the API or to the Claude subscription (D18). The tier job picks the route from the base
toml and this month's records:

| Route | When | How the call runs |
| --- | --- | --- |
| `api` | API-paid reviews today < `reviews_per_day` and API spend this month < `budget_month_usd` | `claude --bare -p`, the federation token through `apiKeyHelper`, cwd = the base checkout |
| `subscription` | an API limit is reached, `[subscription] fallback = true`, the caller passed `claude_code_oauth_token`, and subscription reviews today < `[subscription] reviews_per_day` | `claude -p --safe-mode --strict-mcp-config`, the token in that process's env only, cwd = an empty dir with no `CLAUDE.md` or `.claude` above it |
| none | neither may run, or the budget could not be read | no paid call: `review skipped: budget (<the limits hit>)` |

`--bare` reads no OAuth token, so the subscription call rebuilds its isolation; `tests/test_isolation.py` runs
the pinned CLI on both routes against a fake API and checks that the head's config, the secret dir and the
process env never reach the model, and that both routes send the same system prompt and tools. An API call
refused by the spend limit or for credit is retried once on the subscription when that route may run. A
rejected subscription token is an ERROR, never a budget skip.

Each record says `billing` (`api`, `subscription`, `api+subscription` or null). `cost_usd`,
`budget.reviews_today` and `budget.month_usd` count the API only; `budget.subscription_today` counts
subscription reviews, and `subscription_cost_usd` is the notional cost the subscription paid. Records written
before this field read as API, with no subscription reviews.

The caller grants `actions: read` (the budget reads the caller's own runs this month), `contents: read`,
`checks: read`, `issues: read` (the Spec switch reads the issues a PR closes), `pull-requests: write` and `id-token: write`. It sets `runner` from the
`VERIFICATION_RUNNER` repo variable and holds one concurrency group per PR with `cancel-in-progress: true`.

The gate App posts the check. Each repo's own App (`checks: write`, nothing else) is installed on that repo
alone, and its private key is `VERIFICATION_APP_KEY` in the caller repo's environment `verification-gate`,
whose branch rule names the default branch only: under `pull_request_target` that is the ref every run
carries, and head code naming the environment is refused. The caller passes `app_id`, the key by name
(`secrets: VERIFICATION_APP_KEY: ${{ secrets.VERIFICATION_APP_KEY }}`). A caller that turns the subscription route on
also passes `claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}`; only the review job's claude step
gets the value. The sticky rule and the budget read the
App's records only: any job holding `checks: write`, a PR's own included, can rewrite a GitHub Actions check run,
so the gate's records from before the App count for nothing. With no App id or no key the gate job ends red and
posts nothing.

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
- A `pull_request` run cannot read the gate App's key: the environment's rule names `main` only, so the
  gate job is refused and posts no `verification` check. A branch self-test proves the start, tier, checks
  and review jobs; the verdict and its check are proven on `verify/attack-base` or a `verify/attack-base-*` copy.
- The PR head can edit the caller on its own base, so the attacks that edit workflows (P3, P4c, GATE)
  mean something only on `verify/attack-base`, whose caller sits on `main`.
