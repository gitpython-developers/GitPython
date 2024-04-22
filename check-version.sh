#!/bin/bash
#
# This file is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/
#
# This script checks if we are in a consistent state to build a new release.
# See the release instructions in README.md for the steps to make this pass.
# You may want to run "make release" instead of running this script directly.

set -eEfuo pipefail
trap 'echo "$0: Check failed. Stopping." >&2' ERR

readonly version_path='VERSION'
readonly changes_path='doc/source/changes.rst'

function check_status() {
    git status -s "$@"
    test -z "$(git status -s "$@")"
}

function get_latest_tag() {
    local config_opts
    printf -v config_opts ' -c versionsort.suffix=-%s' alpha beta pre rc RC
    # shellcheck disable=SC2086  # Deliberately word-splitting the arguments.
    git $config_opts tag -l '[0-9]*' --sort=-v:refname | head -n1
}

echo 'Checking current directory.'
test "$(cd -- "$(dirname -- "$0")" && pwd)" = "$(pwd)"  # Ugly, but portable.

echo "Checking that $version_path and $changes_path exist and have no uncommitted changes."
test -f "$version_path"
test -f "$changes_path"
check_status -- "$version_path" "$changes_path"

# This section can be commented out, if absolutely necessary.
echo 'Checking that ALL changes are committed.'
check_status --ignore-submodules

version_version="$(<"$version_path")"
changes_version="$(awk '/^[0-9]/ {print $0; exit}' "$changes_path")"
latest_tag="$(get_latest_tag)"
head_sha="$(git rev-parse HEAD)"
latest_tag_sha="$(git rev-parse "${latest_tag}^{commit}")"

# Display a table of all the current version, tag, and HEAD commit information.
echo
echo 'The VERSION must be the same in all locations, and so must the HEAD and tag SHA'
printf '%-14s = %s\n' 'VERSION file'   "$version_version" \
                      'changes.rst'    "$changes_version" \
                      'Latest tag'     "$latest_tag" \
                      'HEAD SHA'       "$head_sha" \
                      'Latest tag SHA' "$latest_tag_sha"

# Check that the latest tag and current version match the HEAD we're releasing.
test "$version_version" = "$changes_version"
test "$latest_tag" = "$version_version"
test "$head_sha" = "$latest_tag_sha"
echo 'OK, everything looks good.'
