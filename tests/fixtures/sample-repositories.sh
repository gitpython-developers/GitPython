#!/usr/bin/env bash
set -eu

export GIT_AUTHOR_NAME='Fixture Author' GIT_AUTHOR_EMAIL='author@example.com'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"

# Small standalone clone sources, including a nested submodule and older releases.
for project in smmap gitdb; do
    git init -q --object-format=sha1 --ref-format=files -b master "$project"
    printf 'from setuptools import setup\nsetup()\n' > "$project/setup.py"
    printf 'Sample dependency\n' > "$project/README.md"
    printf 'Fixture license\n' > "$project/LICENSE"
    mkdir -p "$project/smmap" "$project/doc"
    printf '# Sample module\n' > "$project/smmap/__init__.py"
    printf 'Sample documentation\n' > "$project/doc/readme"
    if test "$project" = gitdb; then
        rm gitdb/smmap/__init__.py
        printf '[submodule "smmap"]\n\tpath = smmap\n\turl = ../smmap\n' > gitdb/.gitmodules
        git -C gitdb update-index --add --cacheinfo "160000,$(git -C smmap rev-parse HEAD),smmap"
    fi
    for n in $(seq 1 30); do
        printf 'revision %s\n' "$n" > "$project/file"
        git -C "$project" add .
        git -C "$project" commit -qm "Dependency revision $n"
        if test "$n" = 20; then git -C "$project" tag -a v1.0 -m 'Sample release'; fi
    done
done

git init -q --object-format=sha1 --ref-format=files -b master repo
cd repo
printf 'Initial changes\n' > CHANGES
git add CHANGES
git commit -qm 'Initial commit'
git tag root

mkdir -p lib/git git/objects doc test
printf 'Fixture Author\n' > AUTHORS
printf 'Sample repository\n' > README.md
printf '3.0.0\n' > VERSION
printf 'Fixture license\n' > LICENSE
printf 'Sample tests\n' > test/readme
printf '*.pyc\n' > .gitignore
printf 'include README.md\n' > MANIFEST.in
printf 'Sample documentation\n' > doc/readme.txt
printf 'from setuptools import setup\nsetup()\n' > setup.py
printf '# Sample module\nvalue = 1\n' > lib/git/__init__.py
printf '# Another module\n' > lib/git/blob.py
printf '# Sample module\nvalue = 1\n' > git/__init__.py
printf '# Sample object\nvalue = 1\n' > git/objects/blob.py
git add .
git commit -qm 'Add project files'
git tag -a annotated -m 'Annotated release'
git tag tree-layout

for n in $(seq 1 5); do
    printf 'Change %s\n' "$n" >> CHANGES
    git commit -qam "Change $n"
done
git tag base
printf 'Release\n' >> CHANGES
git commit -qam 'Release sample project'
git tag release
printf 'include AUTHORS\n' >> MANIFEST.in
git commit -qam 'Update manifest'
git tag manifest-update

# Two branches with two unique ancestors exercise breadth/depth traversal.
git checkout -qb side
printf 'Side contributor\n' >> AUTHORS
git commit -qam 'Add side contributor'
printf 'Side work\n' > side.txt
git add side.txt
git commit -qm 'Side work'
git checkout -q master
printf 'Main contributor\n' > main.txt
git add main.txt
git commit -qm 'Main work'
printf 'Main changes\n' >> CHANGES
git commit -qam 'More main work'
git merge -q --no-ff side -m 'Merge side work'
git tag merge

# Independent conflicting changes for index and tree merge tests.
git checkout -qb conflict-ours base
printf 'ours\n' > lib/git/__init__.py
git commit -qam 'Our change'
git tag conflict-ours
git checkout -qb conflict-theirs base
printf 'theirs\n' > lib/git/__init__.py
git commit -qam 'Their change'
git tag conflict-theirs
git checkout -q master
git branch -D conflict-ours conflict-theirs

git mv side.txt renamed.txt
git commit -qm 'Rename file'
git tag renamed
GIT_AUTHOR_DATE='2009-10-08T18:17:05 +0200' GIT_COMMITTER_DATE='2009-10-08T20:22:51 +0200' \
    git commit --allow-empty -qm 'Different author and committer dates'
git tag dated

# Historical submodule states use generated dependency commits, never remote data.
mkdir -p git/ext/gitdb
printf '[submodule "old-name"]\n\tpath = git/ext/gitdb\n\turl = ../gitdb\n' > .gitmodules
git add .gitmodules
git update-index --add --cacheinfo "160000,$(git -C ../gitdb rev-parse HEAD~2),git/ext/gitdb"
git commit -qm 'Add submodule'
git update-index --cacheinfo "160000,$(git -C ../gitdb rev-parse HEAD~1),git/ext/gitdb"
git commit -qm 'Advance submodule'
git tag submodule-old
git config -f .gitmodules --rename-section submodule.old-name submodule.gitdb
git add .gitmodules
git update-index --cacheinfo "160000,$(git -C ../gitdb rev-parse HEAD),git/ext/gitdb"
git commit -qm 'Rename and advance submodule'
git tag submodule-current
git rm -q --cached git/ext/gitdb .gitmodules
rm .gitmodules
git commit -qm 'Remove submodule'

for n in $(seq 1 30); do
    printf 'Work %s\n' "$n" >> README.md
    git commit -qam "Work $n"
done
cd ..
git clone -q --bare repo origin
git -C repo remote add origin ../origin
git -C repo fetch -q origin
