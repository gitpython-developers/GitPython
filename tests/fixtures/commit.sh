#!/usr/bin/env bash
set -eu
git init --initial-branch=master repo
cd repo
case "$1" in
    spaces)
        # Construct trees directly: Windows rejects trailing spaces in index paths.
        for multiplier in 1 2; do
            tree=$(
                count=0
                for path in name ' name' 'name ' ' name ' ' '; do
                    count=$((count + 1))
                    oid=$(for ((line=0; line<count*multiplier; line++)); do printf 'line\n'; done | git hash-object -w --stdin)
                    printf '100644 blob %s\t%s\0' "$oid" "$path"
                done | git mktree -z
            )
            if [ "$multiplier" = 1 ]; then
                commit=$(git commit-tree "$tree" -m 'Update files')
            else
                commit=$(git commit-tree "$tree" -p "$commit" -m 'Update files')
            fi
            git tag "update-$multiplier" "$commit"
        done
        commit=$(git commit-tree "$tree" -p "$commit" -m 'No changes')
        git tag empty "$commit"
        tree=$(git mktree </dev/null)
        commit=$(git commit-tree "$tree" -p "$commit" -m 'Remove files')
        git tag removed "$commit"
        git update-ref refs/heads/master "$commit"
        ;;
    ambiguous)
        touch master
        git add master
        git commit -m 'initial commit'
        ;;
    tree|latin1)
        touch hello.txt
        git add hello.txt
        git write-tree > ../tree-id
        if [ "$1" = latin1 ]; then git config i18n.commitencoding ISO-8859-1; fi
        ;;
    raw)
        git hash-object --literally -w -t commit "$2" > ../object-id
        ;;
    encoding)
        tree=$(git mktree </dev/null)
        {
            printf 'tree %s\n' "$tree"
            if [ "$2" = utf8 ]; then
                printf 'author Andr\303\251 <andre@example.com> 1112591163 +0200\n'
                printf 'committer Andr\303\251 <andre@example.com> 1112591163 +0200\n'
            elif [ "$2" = git-only-codec ]; then
                printf 'author \033$)A\016VPND\017 <andre@example.com> 1112591163 +0200\n'
                printf 'committer \033$)A\016VPND\017 <andre@example.com> 1112591163 +0200\n'
            else
                printf 'author Andr\351 <andre@example.com> 1112591163 +0200\n'
                printf 'committer Andr\351 <andre@example.com> 1112591163 +0200\n'
            fi
            case "$2" in
                utf8) printf 'encoding UTF-8\n' ;;
                git-only-codec) printf 'encoding ISO-2022-CN\n' ;;
                latin1|latin1-signature) printf 'encoding ISO-8859-1\n' ;;
                utf16-signature) printf 'encoding utf-16-be\n' ;;
                late-latin1) printf 'x-extra value\nencoding ISO-8859-1\n' ;;
                unknown) printf 'encoding pony-speak\n' ;;
                nontext) printf 'encoding base64_codec\n' ;;
                nonascii) printf 'encoding utf-\3778\n' ;;
                utf16-then-latin1) printf 'encoding utf-16-be\nencoding ISO-8859-1\n' ;;
                utf16be-then-latin1) printf 'encoding UTF-16BE\nencoding ISO-8859-1\n' ;;
                latin1-then-nonascii) printf 'encoding ISO-8859-1\nencoding utf-\3778\n' ;;
                latin1-then-utf8) printf 'encoding ISO-8859-1\nencoding UTF-8\n' ;;
                unknown-then-latin1) printf 'encoding pony-speak\nencoding ISO-8859-1\n' ;;
                empty-then-latin1) printf 'encoding \nencoding ISO-8859-1\n' ;;
                *) exit 1 ;;
            esac
            case "$2" in
                *-signature) printf 'gpgsig sign\351\n continued\351\n' ;;
            esac
            if [ "$2" = utf8 ]; then
                printf '\nR\303\251sum\303\251\n'
            elif [ "$2" = git-only-codec ]; then
                printf '\n\033$)A\016VPND\017\n'
            elif [ "$2" = utf16-then-latin1 ]; then
                # Odd-sized commits force UTF-16 conversion to fail.
                printf '\nR\351sum\351!\n'
            else
                printf '\nR\351sum\351\n'
            fi
        } | git hash-object --literally -w -t commit --stdin > ../object-id
        ;;
esac
