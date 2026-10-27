#!/usr/bin/env bash
set -eu
git init --initial-branch=master repo
cd repo
git commit --allow-empty -m initial
git rev-parse HEAD > ../initial
next=$(printf next | git commit-tree 'HEAD^{tree}' -p HEAD)
printf '%s\n' "$next" > ../next
initial=$(cat ../initial)
write_ref() {
    mkdir -p "$(dirname ".git/$1")"
    printf '%s\n' "$2" > ".git/$1"
}
chain() {
    local count=$1 path=HEAD
    for ((i=1; i<count; i++)); do
        target="refs/heads/link-$i"
        write_ref "$path" "ref: $target"
        path=$target
    done
    write_ref "$path" "$initial"
    printf '%s\n' "$path" > ../terminal
}
case "$1" in
    cycle)
        write_ref HEAD 'ref: refs/heads/a'
        write_ref refs/heads/a "ref: $2"
        write_ref refs/heads/b 'ref: refs/heads/a'
        write_ref refs/tags/loop 'ref: refs/heads/a'
        ;;
    chain|packed|unborn|invalid-write)
        chain "$2"
        terminal=$(cat ../terminal)
        if [ "$1" = packed ]; then
            rm ".git/$terminal"
            write_ref packed-refs "$initial $terminal"
        elif [ "$1" = unborn ]; then
            rm ".git/$terminal"
        elif [ "$1" = invalid-write ] && [ "$3" = cycle ]; then
            write_ref "$terminal" 'ref: refs/heads/link-1'
        fi
        ;;
    lookalike)
        # Valid names Git's revision guessing would accept for missing references.
        git tag refs/heads/missing "$initial"
        git tag REBASE_HEAD "$initial"
        write_ref HEAD 'ref: refs/heads/missing'
        ;;
    custom)
        write_ref CUSTOM_A 'ref: CUSTOM_B'
        write_ref CUSTOM_B 'ref: CUSTOM_A'
        ;;
    external)
        gix_testtools_require_symlinks
        printf '%s\n' "$initial" > ../outside
        ln -s ../../../../outside .git/refs/heads/external
        write_ref HEAD 'ref: refs/heads/external'
        ;;
esac
