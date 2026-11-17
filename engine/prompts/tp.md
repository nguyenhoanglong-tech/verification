This PR changes instruction files that an agent loads: {{PROMPT_FILES}}.
Act as a fresh session that has loaded only the new version of each file from ./pr-head.
1. Pick one realistic case the file is meant for, taken from this repository (name it in "case").
2. Walk through following the instructions on that case, step by step, using Read, Grep and Glob to check every path, command, tool or skill the steps name.
3. Report a blocking finding for a step that cannot be followed: it names something that does not exist, contradicts another step or another loaded rule, or leaves the case without a defined outcome. Report unclear wording as minor.
