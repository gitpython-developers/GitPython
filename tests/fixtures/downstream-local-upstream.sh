#!/usr/bin/env bash
set -eu
git init -q --object-format="$1" --ref-format="$2" repo
cd repo
printf tracked > tracked
git add tracked
git commit -qm initial
git branch upstream
branch=$(git symbolic-ref --short HEAD)
git config "branch.$branch.remote" .
git config "branch.$branch.merge" refs/heads/upstream
