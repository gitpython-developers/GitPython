#!/usr/bin/env bash
set -eu

source=$1
# Include the source revision in the cache identity even though checkout uses history.
source_revision=$2
name=$3
case "$name" in
    gitdb) revision=2da3232f9d58e7761e384ac6d32f7b1ed77a74a2 ;;
    smmap) revision=8ce61ad5cc4016bffaf25080bc0d69b3acbe8555 ;;
    *) printf 'Unknown dependency: %s\n' "$name" >&2; exit 1 ;;
esac

git -C "$source" cat-file -e "$source_revision^{commit}"
git clone --shared --no-checkout "$source" repo
git -C repo checkout -B master "$revision"
if test "$name" = smmap; then
    git -C repo tag -a -f v0.8.1 master~10 -m 'Test fixture tag'
fi
git -C repo gc
