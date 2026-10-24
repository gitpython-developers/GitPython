#!/usr/bin/env bash
set -eu
scenario=$1
git init -q -b main repo
cd repo
git config user.name 'GitPython Tests'
git config user.email gitpython@example.com
mkdir dir
printf 'root\n' > README.md
printf 'root changes\n' > CHANGES
printf 'root file\n' > dir/file.txt
git add .
git commit -qm 'root commit'
root=$(git rev-parse HEAD)
git tag -a ann -m 'annotated tag'
printf 'release\n' > README.md
git add README.md
git commit -qm 'release candidate'
release=$(git rev-parse HEAD)
git tag v1.0
printf 'side\n' > side.txt
git add side.txt
tree=$(git write-tree)
side=$(printf 'side branch' | git commit-tree "$tree" -p "$root")
git branch side "$side"
merge=$(printf 'merge side' | git commit-tree "$tree" -p "$release" -p "$side")
git update-ref -m 'commit: merge side' HEAD "$merge"
git reflog write HEAD "$side" "$merge" 'checkout: moving from side to main'
git branch aaaaaaaa "$merge"
git tag @foo "$merge"
printf 'root %s\nrelease %s\nside %s\nmerge %s\n' "$root" "$release" "$side" "$merge" > ../commits
case "$scenario" in
rev_parse_reflog_selectors)
    git remote add origin ../repo
    git update-ref refs/remotes/origin/main "$merge"
    git config branch.main.remote origin
    git config branch.main.merge refs/heads/main
    ;;
describe-collision)
    abbrev=$(git rev-parse --short=7 "$merge")
    git tag "anything-9-g$abbrev" "$release"
    ;;
rev_parse_preserves_path_metadata_with_colons)
    blob=$(git rev-parse HEAD:dir/file.txt)
    subtree=$(printf '100644 blob %s\tname:with:colons\n' "$blob" | git mktree)
    tree=$(printf '040000 tree %s\tdir\n' "$subtree" | git mktree)
    commit=$(printf 'message: with colon' | git commit-tree "$tree" -p "$merge")
    git update-ref HEAD "$commit"
    case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) git read-tree HEAD ;; esac
    ;;
rev_parse_commit_message_literal_bang_and_option)
    git commit -qm '!urgent --all' --allow-empty
    ;;
rev_parse_commit_message_escaped_braces)
    git commit -qm 'literal{3}' --allow-empty
    git commit -qm literalll --allow-empty
    ;;
backtracking)
    git commit -qm "hello $(printf '%080d' 0 | tr 0 b)" --allow-empty
    ;;
needle)
    git commit -qm needle --allow-empty
    ;;
esac
