#!/usr/bin/env bash
set -eu
git init -q repo
cd repo
git -c user.name=fixture -c user.email=fixture@example.invalid commit --allow-empty -qm initial
# Git rejects each of these files with "bad config line".
case "$1" in
    extra-setting) gitmodules='[submodule "module"]\npath = module\nurl = ../good\nx url = ../evil\n' ;;
    header-setting) gitmodules='[submodule "module"] x url = ../evil\npath = module\n' ;;
    key-comment) gitmodules='[submodule "module"]\npath = module\nurl = ../good\nbr#anch = main\n' ;;
    *) exit 1 ;;
esac
printf '%b' "$gitmodules" > .gitmodules
modules=$(git hash-object -w .gitmodules)
commit=$(git rev-parse HEAD)
tree=$(printf '100644 blob %s\t.gitmodules\000160000 commit %s\tmodule\000' "$modules" "$commit" | git mktree -z)
commit=$(printf 'Add submodule\n' | git -c user.name=fixture -c user.email=fixture@example.invalid commit-tree "$tree" -p "$commit")
git update-ref HEAD "$commit"
