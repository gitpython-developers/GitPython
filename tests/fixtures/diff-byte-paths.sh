#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
git config core.quotePath "$1"
blob=$(printf 'content\n' | git hash-object -w --stdin)
before=$(printf '100644 blob %s\tlegacy-\377\0' "$blob" | git mktree -z)
after=$(printf '100644 blob %s\tlegacy-\376\0' "$blob" | git mktree -z)
parent=$(printf 'before\n' | git commit-tree "$before")
commit=$(printf 'after\n' | git commit-tree "$after" -p "$parent")
git update-ref refs/heads/main "$commit"
