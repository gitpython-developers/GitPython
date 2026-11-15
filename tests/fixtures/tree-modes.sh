#!/usr/bin/env bash
set -eu
git init --initial-branch=main --object-format="$1" repo
cd repo
blob=$(printf 'content\n' | git hash-object -w --stdin)
subtree=$(printf '100644 blob %s\tinner\n' "$blob" | git mktree)
case "$2" in
executable) entry="100700 exe" oid=$blob ;;
symlink) entry="120777 link" oid=$blob ;;
gitlink) entry="140000 sub" oid=$subtree ;;
esac
# git mktree only writes canonical modes, so write the legacy mode literally.
escaped=$(printf %s "$oid" | sed 's/../\\x&/g')
{ printf '%s\0' "$entry"; printf %b "$escaped"; } |
    git hash-object -w -t tree --literally --stdin >../tree-id
git ls-tree "$(cat ../tree-id)" >../entries
