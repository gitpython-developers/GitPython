#!/usr/bin/env bash
set -eu
export MSYS="${MSYS:-} winsymlinks:nativestrict"
export GIT_AUTHOR_NAME='GitPython Tests' GIT_AUTHOR_EMAIL='tests@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git() { command git -c protocol.file.allow=always "$@"; }
source=$(git -C "$1" rev-parse --show-toplevel)
name=$2
scenario=${3:-base}
variant=${4:-none}
root=$PWD
git init -q -b master parent
git -C parent submodule add --name "$name" "$source" module
git -C parent commit -qm 'Create submodule'
case "$scenario" in
    nested)
        git -C parent submodule add --name other "$source" other
        ;;
    existing-nested)
        git clone -q --separate-git-dir="$root/parent/.git/modules/$name/child" "$source" parent/new
        if test "$variant" = retained; then rm -rf parent/new; fi
        ;;
    separate)
        git init -q -b master --separate-git-dir="$root/separate/metadata" separate
        git -C separate submodule add --name module "$source" module
        git -C separate commit -qm 'Add submodule'
        ;;
    intermediate-link)
        target="$root/outside"
        if test "$variant" = internal; then target="$root/parent/target"; fi
        if test "$variant" != dangling; then mkdir "$target"; fi
        mkdir parent/nested
        case "$variant" in
            absolute) ln -s "$target" parent/nested/link ;;
            internal) ln -s ../target parent/nested/link ;;
            *) ln -s ../../outside parent/nested/link ;;
        esac
        git -C parent add nested/link
        git -C parent commit -qm 'Record layout'
        ;;
    leaf-metadata)
        git -C parent worktree add --detach "$root/worktree"
        git -C worktree submodule update --init
        target=$(git -C worktree rev-parse --absolute-git-dir)
        if test "$variant" = common_dir; then target="$root/parent/.git"; fi
        ln -s "$target" worktree/destination
        ;;
    readd-retained)
        git -C parent/module branch preserved
        if test "$(git -C parent/module rev-parse --show-ref-format)" != "$variant"; then
            git -C parent/module refs migrate --ref-format="$variant"
        fi
        git -C parent/module for-each-ref --format='%(refname) %(objectname)' > retained-refs
        git -C parent/module symbolic-ref --short HEAD > retained-branch
        git -C parent/module rev-parse HEAD > retained-commit
        git -C parent/module remote get-url origin > retained-url
        git -C parent rm -f module
        ;;
    reconnect-moved)
        mv parent/module parent/moved
        ;;
    unknown-extension)
        git -C parent/module config core.repositoryFormatVersion 1
        git -C parent/module config extensions.unknown true
        ;;
    logging)
        git -C parent/module branch --unset-upstream
        if test "$variant" = recursive || test "$variant" = keep-going; then
            git -C parent/module submodule add --name child "$source" child
            git -C parent/module commit -qm 'Add child'
            git -C parent/module/child branch --unset-upstream
            git -C parent add module
            git -C parent commit -qm 'Record child'
        fi
        ;;
    retained)
        git -C parent rm -f module
        ;;
esac
