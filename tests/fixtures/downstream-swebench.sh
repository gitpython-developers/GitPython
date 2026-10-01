#!/usr/bin/env bash
set -eu
export GIT_AUTHOR_NAME='GitPython Compatibility' GIT_AUTHOR_EMAIL='tests@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git init -q -b main --object-format="$1" --ref-format="$2" origin
printf 'Local fixture\n' > origin/README.md
printf 'value = 1\n' > origin/module.py
git -C origin add README.md module.py
git -C origin commit -qm initial
git -C origin rev-parse HEAD > first-commit
printf 'value = 2\n' > origin/module.py
git -C origin commit -qam second
git -C origin rev-parse HEAD > second-commit
git config --file gitconfig user.name "$GIT_AUTHOR_NAME"
git config --file gitconfig user.email "$GIT_AUTHOR_EMAIL"
git config --file gitconfig "url.$PWD/origin.insteadOf" https://gitpython-tests@github.com/swe-bench-repos/fixture__project.git
git config --file gitconfig protocol.file.allow always
mkdir checkouts
