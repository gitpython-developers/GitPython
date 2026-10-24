#!/usr/bin/env bash
set -eu
root=$PWD
git init -q -b master source
git -C source commit --allow-empty -qm initial
git init -q -b master parent
git -C parent -c protocol.file.allow=always submodule add "$root/source" module
git -C parent commit -qm 'Add submodule'
if test "$1" = update; then
    git clone -q parent clone
    git clone -q parent baseline
else
    git clone -q source replacement
    git -C parent rev-parse HEAD >previous
    git -C parent config -f .gitmodules submodule.module.url "$root/replacement"
    git -C parent add .gitmodules
    git -C parent commit -qm 'Replace submodule URL'
    git clone -q parent baseline
    git -C baseline -c protocol.file.allow=always submodule update --init
    git -C baseline/module remote set-url origin "$root/source"
fi
