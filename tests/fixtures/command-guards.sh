#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
case "$1" in
    test_merge_base_distinguishes_unrelated_history_from_invalid_options)
        git commit --allow-empty -m first
        tree=$(git rev-parse 'HEAD^{tree}')
        commit=$(printf second | git commit-tree "$tree")
        git update-ref refs/heads/second "$commit"
        ;;
    test_move_checks_unsafe_options)
        git read-tree --empty
        ;;
esac
