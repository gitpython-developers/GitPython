#!/usr/bin/env bash
set -eu
git init -q --initial-branch=main repo
cd repo
# Build the blob directly so trailing whitespace, a whitespace-only line, and a
# CRLF line survive fixture creation on every platform.
blob=$(printf 'alpha   \nbeta\n\t\ncrlf\r\ngamma\n' | git hash-object -w --stdin)
tree=$(printf '100644 blob %s\tfile.txt\0' "$blob" | git mktree -z)
commit=$(GIT_AUTHOR_DATE='2020-01-01T12:00:00+0530' \
    GIT_COMMITTER_DATE='2020-01-01T13:00:00-0400' \
    git -c user.name=A -c user.email=a@example.com commit-tree "$tree" -m content)
git update-ref refs/heads/main "$commit"
git reset --hard -q HEAD
printf 'changed\n' > file.txt
