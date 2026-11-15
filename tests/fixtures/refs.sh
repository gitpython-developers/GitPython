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
    tag-message)
        {
            printf 'object %s\ntype commit\ntag v1\n' "$(git rev-parse HEAD)"
            printf 'tagger T <t@example.com> 1700000000 +0000\n\n'
            case "$3" in
                pgp) printf 'release\n-----BEGIN PGP SIGNATURE-----\nc2ln\n-----END PGP SIGNATURE-----\n' ;;
                ssh) printf 'release\n-----BEGIN SSH SIGNATURE-----\nc2ln\n-----END SSH SIGNATURE-----\n' ;;
                empty-line) printf '\n-----BEGIN PGP SIGNATURE-----\nc2ln\n-----END PGP SIGNATURE-----\n' ;;
                line-feeds) printf '\n\n' ;;
                *) exit 1 ;;
            esac
        } | git hash-object -w -t tag --literally --stdin >../tag-id
        ;;
    rename-prefixed)
        git branch topic
        printf 'second\n' >> file.txt
        git commit -am second
        ;;
    outside)
        git rev-parse HEAD > ../outside-ref
        ;;
    unsafe-branch)
        branch_name="$3"
        git update-ref "refs/heads/$branch_name" HEAD
        git symbolic-ref HEAD "refs/heads/$branch_name"
        cd ..
        git clone repo clone
        printf 'unmatched-private-content\n' > clone/pathspecs
        printf 'uncommitted\n' >> clone/file.txt
        ;;
esac
