#!/usr/bin/env bash
set -eu

git init --object-format="$1" --ref-format="$2" --initial-branch=main source
git -C source commit --allow-empty -m 'Remote history'
for name in refs/heads/unborn REBASE_HEAD ORIG_HEAD refs/tags/missing refs/remotes/origin/missing; do
    git -C source tag "$name"
done
git -C source tag -a nested/release -m 'Annotated release'
if [ "${3-}" = nested ]; then
    git -C source tag -a nested/outer nested/release -m 'Nested annotated release'
fi
git init --object-format="$1" --ref-format="$2" --initial-branch=unborn repo
git -C repo fetch ../source 'refs/tags/*:refs/tags/*'
if [ "${3-}" = symbolic ]; then
    git -C repo symbolic-ref refs/tags/REBASE_HEAD refs/tags/refs/heads/unborn
fi
if [ "${3-}" = shadowed ]; then
    # Fetched tags share the short names of a local branch and a remote-tracking branch.
    git -C repo fetch ../source 'refs/heads/main:refs/tags/main' 'refs/heads/main:refs/tags/origin/main'
    blob=$(printf 'local\n' | git -C repo hash-object -w --stdin)
    tree=$(printf '100644 blob %s\tfile\n' "$blob" | git -C repo mktree)
    commit=$(git -C repo commit-tree -m 'Local history' "$tree")
    for path in refs/heads/main refs/remotes/origin/main; do
        git -C repo update-ref "$path" "$commit"
    done
    git -C repo symbolic-ref HEAD refs/heads/main
fi
if [ "${3-}" = existing ]; then
    commit=$(git -C source rev-parse HEAD)
    for path in refs/heads/unborn refs/stash ORIG_HEAD REBASE_HEAD; do
        git -C repo update-ref "$path" "$commit"
    done
    printf '%s\n' "$commit" >repo/.git/MERGE_HEAD
fi
