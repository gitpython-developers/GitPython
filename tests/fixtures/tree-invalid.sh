#!/usr/bin/env bash
set -eu
git init --initial-branch=main --object-format="$1" repo
cd repo
blob=$(printf 'content\n' | git hash-object -w --stdin)
if test "$2" = first; then
    valid=valid
else
    valid='!valid'
fi
{
    printf '100644 blob %s\t.git\n' "$blob"
    printf '100644 blob %s\t%s\n' "$blob" "$valid"
} | git mktree > ../tree-id
git ls-tree "$(cat ../tree-id)" > ../entries
