#!/bin/sh

set -e

if test -z "$TRAVIS"; then
    printf 'This operation will destroy locally modified files. Continue ? [N/y]: ' >&2
    read -r answer
    case "$answer" in
    [yY])
        ;;
    *)
        exit 2 ;;
    esac
fi

git tag __testing_point__
git checkout master -- || git checkout -b master
git reset --hard HEAD~1
git reset --hard HEAD~1
git reset --hard HEAD~1
git reset --hard __testing_point__

test -z "$TRAVIS" || exit 0  # CI jobs will already have taken care of the rest.

git fetch --all --tags
git submodule update --init --recursive
