#!/usr/bin/env bash
set -eu
git init -q --object-format="$1" --ref-format="$2" repo
cd repo
mkdir dir
printf tracked > tracked
printf nested > dir/file
git add .
git commit -qm 'initial: with colon'
