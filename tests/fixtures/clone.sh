#!/usr/bin/env bash
set -eu
case "$1" in
    test_clone_preserves_literal_separate_git_dir)
        git init --initial-branch=master source
        ;;
    test_clone_clears_ambient_source_storage_environment)
        git init --initial-branch=master source
        git -C source commit --allow-empty -m initial
        ;;
    test_clone_reference_options_allowed)
        git init --initial-branch=master source
        printf 'content\n' > source/file
        git -C source add file
        git -C source commit -m initial
        git clone --no-hardlinks source 'reference repo'
        ;;
    source)
        git init --initial-branch=master repo
        ;;
    nonempty)
        printf 'Garbage!' > not-empty
        ;;
    unicode)
        mkdir Δ
        ;;
esac
