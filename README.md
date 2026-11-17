# verification

The engine behind the merge gate described in chrislongnguyen/dotfiles `claude/docs/verification/DECISIONS.md`.

A repo opts in with a thin `pull_request_target` caller on its default branch that calls
`.github/workflows/gate.yml` pinned by commit SHA, plus `.github/verification.toml` (see `examples/`).
The gate computes the tiers a PR owes from its diff (`engine/tier.py`), runs the owed checks with the
PR head checked out as data, and posts one check run named `verification` from GitHub Actions.

Tests: `python3 tests/test_tier.py`.
