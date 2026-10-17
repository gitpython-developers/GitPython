#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
case "$1" in
    test_delete_head_cannot_override_force)
        git commit --allow-empty -m initial
        tree=$(git rev-parse 'HEAD^{tree}')
        commit=$(printf unmerged | git commit-tree "$tree" -p HEAD)
        git update-ref refs/heads/unmerged "$commit"
        ;;
    test_rename_head_cannot_select_current_branch|test_tag_operands_follow_option_terminator)
        git commit --allow-empty -m initial
        ;;
    test_remote_ref_delete_preserves_operand)
        git commit --allow-empty -m initial
        git update-ref refs/remotes/--force HEAD
        ;;
    test_move_treats_option_shaped_source_as_filename)
        printf 'literal source' > ./--force
        git add -- --force
        ;;
    test_move_cannot_override_overwrite_protection)
        for name in --force source destination; do printf '%s' "$name" > "$name"; done
        git add -- --force source destination
        ;;
    test_ignored_treats_option_shaped_path_as_filename)
        printf '%s\n' --verbose '--arg value' > .gitignore
        ;;
    test_move_cannot_override_dry_run)
        printf source > source
        git add source
        ;;
esac
