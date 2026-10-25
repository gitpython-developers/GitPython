#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
printf 'contents\n' >repo/file
git -C repo add file
git -C repo commit -m initial
git -C repo gc
