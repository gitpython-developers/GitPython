#!/usr/bin/env bash
set -eu
git init -q repo
printf '[remote "origin-\377"]\n\turl = target-\376\n' >> repo/.git/config
cp repo/.git/config config
