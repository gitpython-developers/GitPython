#!/usr/bin/env bash
set -eu

export GIT_AUTHOR_NAME='Benchmark' GIT_AUTHOR_EMAIL='benchmark@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git init --object-format=sha1 --ref-format=files -b main dependency
git -C dependency commit --allow-empty -m 'Dependency'
git init --object-format=sha1 --ref-format=files -b benchmark repo
mkdir -p repo/git/objects repo/dependency
printf 'Sample objects\n' > repo/git/objects/readme
printf '[submodule "dependency"]\n\tpath = dependency\n\turl = ../dependency\n' > repo/.gitmodules
git -C repo update-index --add --cacheinfo "160000,$(git -C dependency rev-parse HEAD),dependency"
for n in $(seq 1 30); do
    printf 'Revision %s\n' "$n" >> repo/README.md
    git -C repo add .
    git -C repo commit -m "Revision $n"
done
git -C repo tag -a v1.0 HEAD~10 -m 'Sample release'
git -C repo config core.excludesFile /dev/null
git -C repo config core.attributesFile /dev/null
git -C repo config core.fsmonitor false
git -C repo config core.untrackedCache false
git -C repo config gc.auto 0
git -C repo config maintenance.auto false
mkdir repo/.benchmark-cache
touch repo/.benchmark-cache/probe repo/benchmark-untracked.txt
echo '.benchmark-cache/' >> repo/.git/info/exclude
