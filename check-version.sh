#!/bin/bash
#
# This script checks if we are in a consistent state to build a new release.
# See the release instructions in README.md for the steps to make this pass.
# You may want to run "make release" instead of running this script directly.

set -eEfuo pipefail
trap 'echo "$0: Check failed. Stopping." >&2' ERR

readonly version_path='VERSION'
readonly changes_path='doc/source/changes.rst'

echo 'Checking current directory.'
test "$(cd -- "$(dirname -- "$0")" && pwd)" = "$(pwd)"  # Ugly, but portable.

echo "Checking that $version_path and $changes_path exist and have no uncommitted changes."
test -f "$version_path"
test -f "$changes_path"
git status -s -- "$version_path" "$changes_path"
test -z "$(git status -s -- "$version_path" "$changes_path")"

# This section can be commented out, if absolutely necessary.
echo 'Checking that ALL changes are committed.'
git status -s --ignore-submodules
test -z "$(git status -s --ignore-submodules)"

version_version="$(cat "$version_path")"
changes_version="$(awk '/^[0-9]/ {print $0; exit}' "$changes_path")"
config_opts="$(printf ' -c versionsort.suffix=-%s' alpha beta pre rc RC)"
latest_tag="$(git $config_opts tag -l '[0-9]*' --sort=-v:refname | head -n1)"
head_sha="$(git rev-parse HEAD)"
latest_tag_sha="$(git rev-parse "${latest_tag}^{commit}")"

# Display a table of all the current version, tag, and HEAD commit information.
echo $'\nThe VERSION must be the same in all locations, and so must the HEAD and tag SHA'
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
