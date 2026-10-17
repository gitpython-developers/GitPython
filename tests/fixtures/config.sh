#!/usr/bin/env bash
set -eu
case "$1" in
empty) : ;;
lock-errors)
    case "$2" in
        missing) : ;;
        unwritable) mkdir parent; chmod 500 parent ;;
        *) exit 1 ;;
    esac
    ;;
values)
    cat > config <<'EOF'
[CoRe]
Flag
number = 1
number = 2
[remote "Origin"]
url = first
EOF
    ;;
includes)
    git init -q repo
    printf '[values]\nsource = included\n' > included
    git config --file config values.source before
    git config --file config include.path "$PWD/included"
    git config --file config --add values.source after
    gitdir=$(git -C repo rev-parse --absolute-git-dir)
    git config --file config "includeIf.gitdir:$gitdir.path" "$PWD/included"
    ;;
multiple)
    printf '[values]\nnumber = 1\n' > one
    printf '[values]\nnumber = 2\n' > two
    ;;
invalid)
    printf '[values]\ninvalid_key = value\n' > config
    ;;
*) exit 1 ;;
esac
