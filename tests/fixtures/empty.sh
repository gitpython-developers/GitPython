#!/usr/bin/env bash
set -eu

# Without arguments this is the initial state for operations that create a repo.
if test "$#" -gt 0; then
    object_format=$1
    ref_format=${2:-files}
    branch=${3:-master}
    bare=${4:-false}
    set --
    if test "$bare" = true; then set -- --bare; fi
    git init --object-format="$object_format" --ref-format="$ref_format" \
        --initial-branch="$branch" "$@" repo
fi
