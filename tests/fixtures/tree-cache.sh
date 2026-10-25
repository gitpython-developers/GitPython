#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
mkdir repo/sub
printf 'original\n' >repo/sub/file
git -C repo add sub/file
git -C repo commit -m initial
