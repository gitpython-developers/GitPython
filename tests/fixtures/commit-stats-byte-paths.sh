#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
git config core.quotePath "$1"
git config diff.algorithm myers
# Tree entries avoid filesystem restrictions on byte and control-character paths.
paths=($'byte-\377' '"byte-\377"' $'utf8-\303\251' $'tab\tname' $'line\nname' 'quote"name' 'back\slash')
binary=$(printf 'binary\0data' | git hash-object -w --stdin)
for multiplier in 1 2; do
    blob=$(for ((line=0; line<multiplier; line++)); do printf 'line\n'; done | git hash-object -w --stdin)
    tree=$(
        {
            for path in "${paths[@]}"; do printf '100644 blob %s\t%s\0' "$blob" "$path"; done
            printf '100644 blob %s\tbinary\tfile\0' "$binary"
        } | git mktree -z
    )
    if [ "$multiplier" = 1 ]; then
        commit=$(git commit-tree "$tree" -m initial)
    else
        commit=$(git commit-tree "$tree" -p "$commit" -m update)
    fi
    git tag "update-$multiplier" "$commit"
done
tree=$(git mktree </dev/null)
commit=$(git commit-tree "$tree" -p "$commit" -m remove)
git update-ref refs/heads/main "$commit"
