Find what this change could break outside the diff before it merges.
1. List every function, file, config key, command or output the diff changes the behavior of.
2. For each one, search the base and pr-head trees for its callers and readers outside the diff (Grep, Glob, Read), and decide whether each still works with the new behavior.
3. Name the one fact the change is safe because of, and check that fact in the code.
Report each caller or reader that breaks as a finding with its file and line.
