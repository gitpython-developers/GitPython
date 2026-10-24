#!/usr/bin/env bash
set -eu
git init -q --object-format="$1" --ref-format="$2" --separate-git-dir=metadata repo
# Keep the fixture relocatable when copied into a writable test directory.
printf 'gitdir: ../metadata\n' > repo/.git
cd repo
printf tracked > tracked
git add tracked
git commit -qm initial
