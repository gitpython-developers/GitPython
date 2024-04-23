#!/bin/sh
#
# This file is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

set -eu

fallback_repo_for_tags='https://github.com/gitpython-developers/GitPython.git'

ci() {
    # For now, check just these, as a false positive could lead to data loss.
    test -n "${TRAVIS-}" || test -n "${GITHUB_ACTIONS-}"
}

no_version_tags() {
    test -z "$(git tag -l '[0-9]*' 'v[0-9]*')"
}

warn() {
    if test -n "${GITHUB_ACTIONS-}"; then
        printf '::warning ::%s\n' "$*" >&2  # Annotate workflow.
    else
        printf '%s\n' "$@" >&2
    fi
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

# The tests need submodules, including a submodule with a submodule.
git submodule update --init --recursive

# The tests need some version tags. Try to get them even in forks. This fetches
# other objects too. So, locally, we always do it, for a consistent experience.
if ! ci || no_version_tags; then
    git fetch --all --tags
fi

# If we still have no version tags, try to get them from the original repo.
if no_version_tags; then
    warn 'No local or remote version tags found. Trying fallback remote:' \
         "$fallback_repo_for_tags"

    # git fetch supports * but not [], and --no-tags means no *other* tags, so...
    printf 'refs/tags/%d*:refs/tags/%d*\n' 0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 |
        xargs git fetch --no-tags "$fallback_repo_for_tags"

    if no_version_tags; then
        warn 'No version tags found anywhere. Some tests will fail.'
    fi
fi
