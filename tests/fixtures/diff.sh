#!/usr/bin/env bash
set -eu
git init --initial-branch=master repo
cd repo
case "$1" in
    stages)
        printf 'hello world' > hello.txt
        git add hello.txt
        git commit -m init
        printf 'Hola Mundo' > hello.txt
        git add hello.txt
        if [ "$2" != staged ]; then git commit -m 'change on master'; fi
        if [ "$2" = conflict ]; then
            git checkout HEAD~1 -b topic
            printf 'Hallo Welt' > hello.txt
            git commit -am 'change on topic branch'
            if git cherry-pick master; then exit 1; fi
        fi
        ;;
    mnemonic)
        printf 'initial\n' > file.txt
        git add file.txt
        git commit -m initial
        printf 'changed\n' > file.txt
        git config diff.mnemonicPrefix true
        if [ "$2" = staged ]; then git add file.txt; fi
        ;;
    rename)
        printf 'hello world\n' > file_a.txt
        git add file_a.txt
        git commit -m 'Added file_a.txt'
        git rm file_a.txt
        printf 'hello world\nhello world' > file_b.txt
        git add file_b.txt
        git commit -m 'Removed file_a.txt. Added file_b.txt'
        ;;
    external)
        printf 'first_line\n' > .gitignore
        git add .gitignore
        git commit -m 'first commit'
        printf 'second_line\n' >> .gitignore
        git commit -am 'second commit'
        printf 'third_line\n' >> .gitignore
        git add .gitignore
        printf 'fourth_line\n' >> .gitignore
        git config diff.external bogus_diff_engine
        ;;
    space)
        printf 'hello world' > ' file.txt'
        git add ' file.txt'
        git commit -m 'first commit'
        ;;
    submodule)
        git init --initial-branch=master ../source
        touch ../source/subfile
        git -C ../source add subfile
        git -C ../source commit -m 'first commit'
        touch test
        git add test
        git -c protocol.file.allow=always submodule add --name subtest ../source sub
        git commit -m 'first commit'
        git tag 1
        printf blub > sub/subfile
        git -C sub commit -am 'changed subfile'
        git add sub
        git commit -m 'submodule changed'
        git tag 2
        ;;
esac
