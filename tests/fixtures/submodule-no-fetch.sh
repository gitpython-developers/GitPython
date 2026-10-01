#!/usr/bin/env bash
set -eu
export GIT_AUTHOR_NAME='GitPython Tests' GIT_AUTHOR_EMAIL='tests@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git() { command git -c protocol.file.allow=always "$@"; }
commit_file() {
    printf '%s' "$2" > "$1/file"
    git -C "$1" add file
    git -C "$1" commit -qm "Write $2"
}
pin() {
    git -C parent update-index --cacheinfo "160000,$1,module"
    git -C parent commit -qm "$2"
}
scenario=$1
uninitialized=$2
latest=$3
change_branch=$4
multiple_remotes=$5
# Keep an alias in URLs so path identity cannot substitute for Git's exact spelling.
root=$PWD/.
git init -q -b master source
commit_file source initial
commit_file source cached
git -C source tag cached
git init -q -b master parent
git -C parent submodule add -b master "$root/source" module
git -C parent commit -qm 'Add submodule'
module=parent/module
case "$scenario" in
    test_update_no_fetch_checks_out_cached_commit)
        git -C "$module" remote add backup "$root/source"
        git -C "$module" reset --hard HEAD~1
        ;;
    test_update_no_fetch_to_latest_revision_uses_cached_tip)
        git -C "$module" reset --hard HEAD~1
        pin "$(git -C "$module" rev-parse HEAD)" 'Pin submodule to initial commit'
        commit_file source remote-only
        ;;
    test_update_no_fetch_cannot_check_out_missing_commit)
        commit_file source remote-only
        pin "$(git -C source rev-parse HEAD)" 'Pin submodule to uncached commit'
        ;;
    test_update_no_fetch_restores_deinitialized_submodule)
        git -C "$module" reset --hard HEAD~1
        if test "$latest" = True; then
            pin "$(git -C "$module" rev-parse HEAD)" 'Pin submodule to initial commit'
        fi
        git -C parent submodule deinit --force module
        commit_file source remote-only
        ;;
    test_update_after_deinit_fetches_remote_tip)
        git -C parent submodule deinit module
        commit_file source remote-only
        ;;
    test_update_no_fetch_is_recursive)
        git -C "$module" submodule add -b master "$root/source" nested
        cached=$(git -C "$module/nested" rev-parse HEAD)
        git -C "$module/nested" reset --hard HEAD~1
        git -C "$module" add nested
        git -C "$module" commit -qm 'Add nested submodule at initial commit'
        previous=$(git -C "$module" rev-parse HEAD)
        git -C "$module" update-index --cacheinfo "160000,$cached,nested"
        git -C "$module" commit -qm 'Advance nested submodule'
        pin "$(git -C "$module" rev-parse HEAD)" 'Record nested submodule update'
        git -C "$module" reset --hard "$previous"
        ;;
    test_root_update_no_fetch_on_branch_change)
        git -C source branch master-other
        git -C "$module" fetch origin
        git -C parent tag previous
        git -C parent config -f .gitmodules submodule.module.branch master-other
        git -C parent add .gitmodules
        git -C parent commit -qm 'Change submodule branch'
        git -C "$module" reset --hard HEAD~1
        ;;
    test_root_update_no_fetch_on_url_change|test_root_update_no_fetch_url_change_uses_cached_tip|test_root_update_no_fetch_selects_url_change_remote)
        branch=master
        if test "$change_branch" = True; then
            branch=master-other
            git -C source branch "$branch"
            git -C "$module" fetch origin
        fi
        if test "$scenario" = test_root_update_no_fetch_selects_url_change_remote; then
            git -C "$module" remote set-url origin "$root/unrelated"
            if test "$multiple_remotes" = True; then
                git -C "$module" remote add upstream "$root/source"
                git -C "$module" fetch upstream
                git -C "$module" branch --set-upstream-to=upstream/master master
            else
                git -C "$module" remote rename origin upstream
            fi
        fi
        git -C "$module" reset --hard HEAD~1
        if test "$scenario" = test_root_update_no_fetch_url_change_uses_cached_tip; then
            pin "$(git -C "$module" rev-parse HEAD)" 'Pin submodule to initial commit'
        fi
        git -C parent tag previous
        git clone -q source mirror
        if test "$scenario" = test_root_update_no_fetch_url_change_uses_cached_tip; then
            if test "$change_branch" = True; then git -C mirror checkout -b "$branch"; fi
            commit_file mirror remote-only
        fi
        git -C parent config -f .gitmodules submodule.module.url "$root/mirror"
        git -C parent config -f .gitmodules submodule.module.branch "$branch"
        git -C parent add .gitmodules
        git -C parent commit -qm 'Change submodule URL and tracking branch'
        ;;
esac
case "$uninitialized" in
    missing|deinitialized)
        git -C parent submodule deinit --force module
        if test "$uninitialized" = missing; then rm -rf parent/.git/modules/module; fi
        ;;
esac
if test "$scenario" = test_update_no_fetch_preserves_nonempty_deinitialized_checkout; then
    printf '%s' 'user content' > parent/module/file
fi
