#!/usr/bin/env bash
set -eu
git init -q -b main --object-format="$1" repo
git -C repo commit -qm initial --allow-empty
blob=$(printf data | git -C repo hash-object -w --stdin)
commit=$(git -C repo rev-parse HEAD)
write_entry () {
    printf '%s %s\0' "$1" "$2"
    printf '%b' "$(printf %s "$3" | sed 's/../\\x&/g')"
}
{
    write_entry 100700 executable "$blob"
    case "$2" in
    gitlink) write_entry 140000 module "$commit" ;;
    missing-mode) write_entry '' module "$commit" ;;
    zero-mode) write_entry 0 module "$commit" ;;
    esac
    write_entry 120777 symlink "$blob"
} | git -C repo hash-object --literally -w -t tree --stdin >tree-id
