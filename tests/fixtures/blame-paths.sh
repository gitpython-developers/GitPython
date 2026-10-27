#!/usr/bin/env bash
set -eu
# C-quoted tree input preserves control bytes through Windows fixture creation.
paths=('plain.txt' ' spaced name.txt ' '"caf\303\251.txt"' '"byte-\377.txt"' '"\"literal-\\303\\251.txt\""' '"quote\"name.txt"' '"back\\slash.txt"' '"control\a\b\t\n\v\f\r.txt"')
for i in "${!paths[@]}"; do
    git init -q --initial-branch=main "$i"
    (
        cd "$i"
        git config core.quotePath "$1"
        blob=$(printf 'first\nmiddle\nlast\n' | git hash-object -w --stdin)
        tree=$(printf '100644 blob %s\t%s\n' "$blob" "${paths[$i]}" | git mktree)
        original=$(git commit-tree "$tree" -m original)
        tree=$(printf '100644 blob %s\tcurrent.txt\0' "$blob" | git mktree -z)
        renamed=$(git commit-tree "$tree" -p "$original" -m rename)
        blob=$(printf 'first\nchanged\nlast\n' | git hash-object -w --stdin)
        tree=$(printf '100644 blob %s\tcurrent.txt\0' "$blob" | git mktree -z)
        edited=$(git commit-tree "$tree" -p "$renamed" -m edit)
        git update-ref refs/heads/main "$edited"
    )
done
