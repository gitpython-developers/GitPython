#!/usr/bin/env bash
set -eu
export GIT_AUTHOR_NAME='GitPython Tests' GIT_AUTHOR_EMAIL='tests@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git init -q -b master source
printf content > source/file
git -C source add file
git -C source commit -qm 'Create source'
