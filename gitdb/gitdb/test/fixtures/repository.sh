#!/usr/bin/env bash
set -eu
git init -q --object-format=sha1 -b main repo
cd repo
for n in $(seq 1 30); do
    printf 'revision %s\n' "$n" >> file
    git add file
    git commit -qm "Revision $n"
done
git gc --prune=now
# Keep both packed and loose objects for the compound database and tutorial tests.
printf 'loose object\n' > loose
git add loose
git commit -qm 'Add loose objects'
