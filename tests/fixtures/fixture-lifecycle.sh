#!/usr/bin/env bash
set -eu

git init --initial-branch=master repo
printf initial >repo/file
git -C repo add file
git -C repo commit -m 'Initial fixture'
git -C repo rev-parse --show-toplevel >location
printf '%s\n' "${1:-default}" >scenario
