#!/usr/bin/env bash
set -eu

git init --initial-branch=main repo
cd repo
mkdir dir1 Downloads
for path in dir1/file1.txt dir1/file2.txt Downloads/file3.txt file4.txt; do
    printf 'File version 1\n' > "$path"
done
git add .
git commit -m 'Initial tutorial files'
