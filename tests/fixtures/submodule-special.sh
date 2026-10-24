#!/usr/bin/env bash
set -eu
export GIT_AUTHOR_NAME='GitPython Tests' GIT_AUTHOR_EMAIL='tests@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git() { command git -c protocol.file.allow=always "$@"; }
case "$1" in
    literal-name)
        # MSYS can expand metacharacters in arguments from native Windows callers.
        # shellcheck disable=SC2016
        case "$2" in
            plain) name='module' ;;
            dollar) name='$GITPYTHON_TEST_SECRET' ;;
            braced-dollar) name='prefix-${GITPYTHON_TEST_SECRET}-suffix' ;;
            percent) name='%GITPYTHON_TEST_SECRET%' ;;
            *) exit 1 ;;
        esac
        git init -q -b master source
        git -C source commit --allow-empty -qm 'Initial commit'
        git init -q -b master parent
        git -C parent submodule add --name "$name" "$PWD/source" module
        git -C parent commit -qm 'Add submodule'
        git clone -q parent clone
        ;;
    lifecycle)
        git init -q -b master --object-format="$2" --ref-format="$3" source
        git init -q -b master --object-format="$2" --ref-format="$3" parent
        printf content > source/file
        git -C source add file
        git -C source commit -qm 'Initial commit'
        ;;
    open-metadata)
        git init -q -b master --separate-git-dir="$PWD/metadata" checkout
        touch metadata/objects/held-open
        ;;
esac
