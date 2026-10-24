#!/usr/bin/env bash
set -eu
root=$PWD
git init -q -b master source
git -C source commit --allow-empty -qm initial
git init -q -b master parent
git -C parent -c protocol.file.allow=always submodule add "$root/source" module
git -C parent commit -qm 'Add submodule'
git clone -q parent clone
git clone -q parent baseline
