#!/usr/bin/env bash
set -eu

git init --object-format=sha1 --ref-format=files repo
git -C repo fetch --no-tags "$1" 6ba2c0a2f9ee7feffd7e079621c4845820180c9a
git -C repo checkout -b benchmark FETCH_HEAD
git -C repo config core.excludesFile /dev/null
git -C repo config core.attributesFile /dev/null
git -C repo config core.fsmonitor false
git -C repo config core.untrackedCache false
git -C repo config gc.auto 0
git -C repo config maintenance.auto false
mkdir repo/.benchmark-cache
touch repo/.benchmark-cache/probe repo/benchmark-untracked.txt
echo '.benchmark-cache/' >> repo/.git/info/exclude
