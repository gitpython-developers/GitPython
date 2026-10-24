#!/usr/bin/env bash
set -eu

git init --initial-branch=main --object-format="${2:-sha1}" --ref-format="${3:-files}" source
git -C source commit --allow-empty -m first
case "$1" in
    fetch)
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C source commit --allow-empty -m second
        ;;
    quoted)
        git init --initial-branch=main parent
        ;;
esac
