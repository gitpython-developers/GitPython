#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
mkdir file
touch bin bin.d file.to file.toml file.toml.bin file0 file/a
git add .
git commit -m c1
git ls-tree --name-only HEAD > ../order
