#!/usr/bin/env bash
set -eu
mkdir -p source/git
printf '1.0\n' > source/VERSION
printf 'value = 1\n' > source/git/module.py
cp -R source copy
cp -R source moved
printf 'value = 2\n' > copy/git/module.py
