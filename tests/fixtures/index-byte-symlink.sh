#!/usr/bin/env bash
set -eu
gix_testtools_require_symlinks
git init --initial-branch=main repo
ln -s "$(printf '../target-\377')" repo/link
