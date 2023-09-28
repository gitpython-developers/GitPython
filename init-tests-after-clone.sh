#!/bin/sh

set -eu

ci() {
    # For now, check just these, as a false positive could lead to data loss.
    test -n "${TRAVIS-}" || test -n "${GITHUB_ACTIONS-}"
}

if ! ci; then
    printf 'This operation will destroy locally modified files. Continue ? [N/y]: ' >&2
    read -r answer
    case "$answer" in
    [yY])
        ;;
    *)
        exit 2 ;;
    esac
fi

# Stop if we have run this. (You can delete __testing_point__ to let it rerun.)
# This also keeps track of where we are, so we can get back here.
git tag __testing_point__

# The tests need a branch called master.
git checkout master -- || git checkout -b master

# The tests need a reflog history on the master branch.
git reset --hard HEAD~1
git reset --hard HEAD~1
git reset --hard HEAD~1

# Point the master branch where we started, so we test the correct code.
git reset --hard __testing_point__

# Do some setup that CI takes care of but that may not have been done locally.
if ! ci; then
    # The tests need some version tags. Try to get them even in forks.
    git fetch --all --tags

    # The tests need submodules, including a submodule with a submodule.
    git submodule update --init --recursive
fi
