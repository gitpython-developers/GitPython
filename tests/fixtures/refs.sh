#!/usr/bin/env bash
set -eu
git init --initial-branch=master --object-format="${2:-sha1}" repo
cd repo
printf 'initial\n' > file.txt
git add file.txt
git commit -m initial
case "$1" in
    security|symlink)
        git symbolic-ref SAFE_RENAME_SOURCE refs/heads/master
        printf 'do not delete\n' > ../outside_delete.txt
        printf 'do not delete\n' > ../outside_remote_delete.txt
        if test "$1" = symlink; then
            mkdir ../outside_refs
            ln -s ../../../../outside_refs .git/refs/heads/link_out
        fi
        ;;
    tag-headers)
        {
            printf 'object %s\ntype commit\n' "$(git rev-parse HEAD)"
            printf 'tag v1\342\200\250tagger Linus Torvalds <torvalds@linux-foundation.org> 1700000000 +0000\n'
            printf 'tagger Mallory <m@evil.example> 1700000001 +0000\n\nrelease\n'
        } | git hash-object -w -t tag --literally --stdin >../tag-id
        ;;
    tag-no-tagger)
        {
            printf 'object %s\ntype commit\ntag no-tagger\n\n' "$(git rev-parse HEAD)"
            if test "$3" = message; then
                printf 'release\nmore\n'
            fi
        } | git hash-object -w -t tag --literally --stdin >../tag-id
        ;;
    outside)
        git rev-parse HEAD > ../outside-ref
        ;;
    unsafe-branch)
        git update-ref 'refs/heads/--pathspec-from-file=pathspecs' HEAD
        git symbolic-ref HEAD 'refs/heads/--pathspec-from-file=pathspecs'
        cd ..
        git clone repo clone
        printf 'unmatched-private-content\n' > clone/pathspecs
        ;;
esac
