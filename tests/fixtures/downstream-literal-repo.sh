#!/usr/bin/env bash
set -eu
# Preserve the literal variable spelling to detect accidental expansion.
# shellcheck disable=SC2016
for path in '$DOWNSTREAM_REPOSITORY' expanded; do
    git init -q --object-format="$1" --ref-format="$2" "$path"
    printf '%s' "$path" > "$path/tracked"
    git -C "$path" add tracked
    git -C "$path" commit -qm initial
done
