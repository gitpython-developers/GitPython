#!/usr/bin/env bash
set -eu

if test "$1" = worktree; then
    git clone --shared "$2" repo
    git -C repo worktree add -b aaaaaaaa ../worktree_repo "$3"
    exit
fi

git init --initial-branch=master repo
a=0101010101010101010101010101010101010101
b=0202020202020202020202020202020202020202
c=0303030303030303030303030303030303030303
entry() { printf '%s %s %s\t%s\n' "$1" "$2" "$3" "$4"; }
tree() { git -C repo mktree --missing >"$1"; }
entry 100644 blob "$a" basefile | tree base
{ entry 100644 blob "$a" basefile; entry 100644 blob "$b" 1; } | tree add-ours
{ entry 100644 blob "$a" basefile; entry 100644 blob "$c" 2; } | tree add-theirs
entry 100644 blob "$b" 1 | tree only-ours
entry 100644 blob "$c" 2 | tree only-theirs
entry 100644 blob "$c" 1 | tree same-name-theirs
entry 160000 commit "$b" 1 | tree gitlink-one
entry 100644 blob "$b" basefile | tree modify-ours
entry 100644 blob "$c" basefile | tree modify-theirs
entry 160000 commit "$a" basefile | tree gitlink-base
entry 100755 blob "$a" basefile | tree executable-base
tree empty </dev/null
