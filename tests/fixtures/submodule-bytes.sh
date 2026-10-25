#!/usr/bin/env bash
set -eu
git init -q repo
cd repo
git -c user.name=fixture -c user.email=fixture@example.invalid commit --allow-empty -qm initial
case "$1" in
    ascii-name) name=module ;;
    byte-name) name=$'module-\377' ;;
    *) exit 1 ;;
esac
printf '[submodule "%s"]\npath = path-\376\nurl = url-\375\nbranch = refs/heads/branch-\374\n' "$name" > .gitmodules
modules=$(git hash-object -w .gitmodules)
commit=$(git rev-parse HEAD)
tree=$(printf '100644 blob %s\t.gitmodules\000160000 commit %s\tpath-\376\000' "$modules" "$commit" | git mktree -z)
commit=$(printf 'Add submodule\n' | git -c user.name=fixture -c user.email=fixture@example.invalid commit-tree "$tree" -p "$commit")
git update-ref HEAD "$commit"
