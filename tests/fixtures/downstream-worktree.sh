#!/usr/bin/env bash
set -eu
git init -q --object-format="$1" --ref-format="$2" repo
cd repo
printf original > tracked
git add tracked
git commit -qm initial
git worktree add -q --no-checkout -b linked ../linked HEAD
printf unchanged > tracked
git init -q ../other
cd ../other
printf other > tracked
git add tracked
git commit -qm other
