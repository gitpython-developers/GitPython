#!/bin/sh

set -e

mkdir dir1
touch dir1/file
chmod -w dir1/file
printf 'Permissions BEFORE rmtree call:\n'
ls -l dir1/file
printf '\n'

mkdir dir2
ln -s ../dir1/file dir2/symlink
chmod -w dir2
python -c 'from git.util import rmtree; rmtree("dir2")' || true
printf '\nPermissions AFTER rmtree call:\n'
ls -l dir1/file
