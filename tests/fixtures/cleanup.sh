#!/usr/bin/env bash
set -eu

case "$1" in
    nested)
        mkdir -p owned/nested
        touch owned/nested/locked owned/nested/removable owned/removable
        ;;
    readonly)
        mkdir owned
        touch owned/readonly
        chmod a-w owned/readonly
        if test "${OS:-}" = Windows_NT; then chmod a-w owned; fi
        ;;
    symlink)
        gix_testtools_require_symlinks
        mkdir owned outside
        printf keep >outside/readonly
        chmod a-w outside/readonly
        ln -s ../outside owned/link
        ;;
    locked)
        mkdir owned
        touch owned/locked owned/removable
        ;;
    source)
        git init --initial-branch=master source
        GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid \
            GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid \
            git -C source commit --allow-empty -m fixture
        ;;
    *) printf 'Unknown cleanup fixture: %s\n' "$1" >&2; exit 1 ;;
esac
