#!/usr/bin/env bash
set -eu
git init --initial-branch=main --object-format="$1" repo
git init --bare --initial-branch=main --object-format="$1" upstream
cd repo
git remote add origin ../upstream
tree=$(git mktree </dev/null)
commit=$(git commit-tree "$tree" -m initial)
git update-ref refs/heads/main "$commit"
for separator in $'\302\205' $'\342\200\250' $'\342\200\251'; do
    git config --add remote.unicode.url "https://example.invalid/before${separator}after"
    for prefix in refs/heads refs/tags refs/remotes/origin; do
        for name in "${separator}after" "before${separator}after" "before${separator}"; do
            git update-ref "$prefix/$name" "$commit"
        done
    done
done
