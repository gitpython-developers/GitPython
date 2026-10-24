#!/usr/bin/env bash
set -eu
git init --initial-branch=master repo
cd repo
case "$1" in
    patch-paths)
        binary=$(printf '\0' | git hash-object -w --stdin)
        empty=$(printf '' | git hash-object -w --stdin)
        docs=$(printf '100644 blob %s\tempty\0' "$empty" | git mktree -z)
        copy=$(printf '100644 blob %s\tlogo.png\0' "$binary" | git mktree -z)
        quoted=$(printf '100644 blob %s\ttab\0' "$binary" | git mktree -z)
        for mode in 100644 100755; do
            assets=$(printf '%s blob %s\tlogo.png\0' "$mode" "$binary" | git mktree -z)
            tree=$({
                printf '040000 tree %s\tassets b\0' "$assets"
                printf '040000 tree %s\tdocs a\0' "$docs"
                printf '040000 tree %s\tquoted\t a\0' "$quoted"
                if [ "$mode" = 100755 ]; then printf '040000 tree %s\tcopy b\0' "$copy"; fi
            } | git mktree -z)
            if [ "$mode" = 100644 ]; then
                parent=$(git commit-tree "$tree" -m paths)
                git update-ref refs/heads/initial "$parent"
            else
                commit=$(git commit-tree "$tree" -p "$parent" -m 'mode change and copy')
                git update-ref refs/heads/master "$commit"
            fi
        done
        ;;
    patch-long-path)
        empty=$(printf '' | git hash-object -w --stdin)
        printf -v path 'x %.0s' {1..250000}
        for mode in 100644 100755; do
            tree=$(printf '%s blob %s\t%s\0' "$mode" "$empty" "$path" | git mktree -z)
            git update-ref "refs/tags/mode-$mode" "$tree"
        done
        ;;
    raw-paths)
        # Build trees directly: Windows cannot create colon/line-feed paths.
        blob=$(printf x | git hash-object -w --stdin)
        fake_meta=':100644 100644 1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 M'
        docs=$({
            printf '100644 blob %s\ta\n%s\0' "$blob" "$fake_meta"
            printf '100644 blob %s\tb\0' "$blob"
        } | git mktree -z)
        tree=$({
            printf '100644 blob %s\t:planted\0' "$blob"
            printf '040000 tree %s\tdocs\0' "$docs"
            printf '100644 blob %s\tsetup.py\0' "$blob"
        } | git mktree -z)
        commit=$(git commit-tree "$tree" -m paths)
        git update-ref refs/heads/master "$commit"
        ;;
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
