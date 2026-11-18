#!/usr/bin/env bash
# Self-test an engine branch without pushing it to dev. See README.md, "Self-test a branch".
#
#   selftest/branch.sh start <branch> [--code]   base verify/selftest/<branch> + one throwaway PR into it
#   selftest/branch.sh stop <branch>             close that PR, delete its head and the base
set -euo pipefail
repo=${SELFTEST_REPO:-nguyenhoanglong-tech/verification}
cmd=${1:-} branch=${2:-} code=${3:-}
[ -n "$branch" ] && { [ "$cmd" = start ] || [ "$cmd" = stop ]; } || { sed -n '3,5p' "$0" >&2; exit 2; }
base=verify/selftest/$branch head=selftest-pr/$branch

tip() { gh api "repos/$repo/git/ref/heads/$1" --jq .object.sha; }

put() { # branch path message content
  local sha args=()
  sha=$(gh api "repos/$repo/contents/$2?ref=$1" --jq .sha 2>/dev/null) && args=(-f "sha=$sha")
  gh api -X PUT "repos/$repo/contents/$2" -f "branch=$1" -f "message=$3" \
    -f "content=$(printf '%s' "$4" | base64 | tr -d '\n')" ${args[@]+"${args[@]}"} --jq .commit.sha
}

raw() { gh api "repos/$repo/contents/$2?ref=$1" -H "Accept: application/vnd.github.raw"; }

if [ "$cmd" = stop ]; then
  for pr in $(gh pr list -R "$repo" --head "$head" --state open --json number --jq '.[].number'); do
    gh pr close "$pr" -R "$repo" --comment "Self-test finished."
  done
  for ref in "$head" "$base"; do
    gh api -X DELETE "repos/$repo/git/refs/heads/$ref" 2>/dev/null && echo "deleted $ref" || echo "absent $ref"
  done
  exit 0
fi

echo "engine branch $branch at $(tip "$branch")"
gh api "repos/$repo/git/refs" -f "ref=refs/heads/$base" -f "sha=$(tip verify/attack-base)" --jq .object.sha >/dev/null
# GitHub reads pull_request workflows from the PR's merge commit, so this caller, committed to the base,
# runs the gate from the named branch. pull_request_target would read only the default branch (D24).
put "$base" .github/workflows/selftest-branch.yml "selftest: call gate.yml@$branch" "# Written by selftest/branch.sh. PRs into $base run the gate from engine branch $branch.
name: verification
on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: [$base]
permissions: {}
concurrency:
  group: verification-selftest-\${{ github.event.pull_request.number }}
  cancel-in-progress: true
jobs:
  verification:
    permissions:
      contents: read
      checks: write
      pull-requests: write
      id-token: write
    uses: $repo/.github/workflows/gate.yml@$branch
    with:
      engine_ref: $branch
" >/dev/null
# Enforce, as on verify/attack-base, so a failure reads as failure rather than neutral.
put "$base" .github/verification.toml "selftest: enforce on $base" \
  "$(raw "$base" .github/verification.toml | sed 's/^mode = .*/mode = "enforce"/')" >/dev/null

gh api "repos/$repo/git/refs" -f "ref=refs/heads/$head" -f "sha=$(tip "$base")" --jq .object.sha >/dev/null
if [ "$code" = --code ]; then
  put "$head" sandbox/calc.py "selftest: one code line (T1)" "$(raw "$head" sandbox/calc.py)
# selftest probe" >/dev/null
else
  put "$head" selftest-probe.md "selftest: docs only (T0)" "Self-test probe for $branch." >/dev/null
fi
gh pr create -R "$repo" --base "$base" --head "$head" --title "selftest $branch (throwaway)" \
  --body "Runs the gate from engine branch \`$branch\`. Close with \`selftest/branch.sh stop $branch\`."
