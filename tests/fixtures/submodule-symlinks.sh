#!/usr/bin/env bash
set -eu
args=("$@")
# shellcheck source=tests/fixtures/submodule-layout.sh
source "$(dirname "${BASH_SOURCE[0]}")/submodule-layout.sh" "$1" "$2"
scenario=${args[2]}
kind=${args[3]}
dangling=${args[4]}
relative_target=${args[6]}
modules="$root/parent/.git/modules"
target="$root/outside"
case "$scenario" in
    test_move_leaf_symlink_compatibility)
        case "$kind" in
            empty|nonempty) mkdir "$target" ;;
            file) printf keep > "$target" ;;
        esac
        if test "$kind" = nonempty; then printf keep > "$target/keep"; fi
        ln -s "$target" parent/destination
        ;;
    test_clone_rejects_checkout_symlinks)
        if test "$dangling" = False; then mkdir "$target"; fi
        ln -s "$target" parent/link
        ;;
    test_submodule_rejects_checkout_and_gitmodules_symlinks)
        path=parent/module
        if test "$kind" = gitmodules; then path=parent/.gitmodules; fi
        mv "$path" "$target"
        ln -s "$target" "$path"
        mkdir parent/moved
        ;;
    test_submodule_allows_symlink_above_worktree)
        ln -s "$root/parent" alias
        ;;
    test_submodule_allows_metadata_destination_symlinks)
        mkdir "$target"
        ln -s "$target" "$modules/link"
        ;;
    test_submodule_allows_existing_metadata_symlinks|test_remove_linked_metadata_keeps_siblings_and_can_reinitialize)
        if test "$scenario" = test_remove_linked_metadata_keeps_siblings_and_can_reinitialize; then
            git -C parent submodule add --name nested/sibling "$source" sibling
            git -C parent commit -qm 'Add sibling'
        fi
        case "$kind" in
            modules) link="$modules" ;;
            intermediate) link="$modules/nested" ;;
            leaf) link="$modules/nested/module" ;;
            gitfile) link="$root/parent/module/.git" ;;
            config) link="$modules/nested/module/config" ;;
            alias)
                link="$modules/alias"
                target="$modules/nested"
                printf 'gitdir: ../.git/modules/alias/module' > parent/module/.git
                ;;
        esac
        if test "$kind" != alias; then mv "$link" "$target"; fi
        ln -s "$target" "$link"
        git config --file "$modules/nested/module/config" core.worktree "$root/parent/module"
        if test "$scenario" = test_remove_linked_metadata_keeps_siblings_and_can_reinitialize; then
            git config --file "$modules/nested/sibling/config" core.worktree "$root/parent/sibling"
        fi
        ;;
    test_add_to_dangling_metadata_symlink)
        target="$root/missing/metadata"
        # Windows determines the native symlink type from the existing target.
        mkdir -p "$target"
        if test "$relative_target" = True; then
            ln -s ../../../missing/metadata "$modules/new"
        else
            ln -s "$target" "$modules/new"
        fi
        rmdir "$target" "$root/missing"
        ;;
esac
