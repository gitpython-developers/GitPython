#!/usr/bin/env bash
set -eu
git init --initial-branch=main --object-format="$1" repo
cd repo
tree=$(git mktree </dev/null)
commit=$(printf initial | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
tag=$(printf 'object %s\ntype commit\ntag annotated\ntagger Example <example@example.invalid> 1100000000 +0000\n\nrelease\n' "$commit" | git hash-object -t tag -w --stdin)
# Packed refs can carry bytes that the fixture filesystem rejects in loose names.
printf '# pack-refs with: peeled fully-peeled sorted\n%s refs/tags/annotated-\343\n^%s\n%s refs/tags/release-\365\n' \
    "$tag" "$commit" "$commit" >.git/packed-refs
