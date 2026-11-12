#!/usr/bin/env bash
set -eu
git init -q --initial-branch=main repo
cd repo
printf 'committed\n' > file.txt
git add file.txt
GIT_AUTHOR_DATE='2020-01-01T12:00:00+0530' \
GIT_COMMITTER_DATE='2020-01-01T13:00:00-0400' \
git commit -q -m initial
printf 'changed\n' > file.txt
