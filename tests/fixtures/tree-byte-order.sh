#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
blob=$(printf 'content\n' | git hash-object -w --stdin)
tree=$({
    printf '100644 blob %s\tname-\377\0' "$blob"
    printf '100644 blob %s\tname-\360\237\222\251\0' "$blob"
} | git mktree -z)
commit=$(printf 'initial\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree --name-only -z HEAD >../order
