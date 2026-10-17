#!/usr/bin/env bash
set -eu

git init --initial-branch=main repo
git -C repo commit --allow-empty -m 'initial commit'
