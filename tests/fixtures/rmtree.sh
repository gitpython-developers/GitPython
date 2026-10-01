#!/usr/bin/env bash
set -eu

case "$1" in
    test_deletes_nested_dir_with_files)
        mkdir -p testdir/q testdir/s
        touch testdir/p testdir/q/w testdir/q/x testdir/r testdir/s/y testdir/s/z
        ;;
    test_deletes_dir_with_readonly_files)
        mkdir -p testdir/sub
        touch testdir/x testdir/sub/y
        chmod 000 testdir/x testdir/sub/y
        ;;
    test_avoids_changing_permissions_outside_tree)
        mkdir dir1 dir2
        touch dir1/file
        chmod 400 dir1/file
        ln -s ../dir1/file dir2/symlink
        chmod 500 dir2
        ;;
esac
