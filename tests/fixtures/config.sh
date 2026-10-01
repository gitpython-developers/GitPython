#!/usr/bin/env bash
set -eu
case "$1" in
continued-values)
    case "$2" in
        0) printf '%s' $'[a]\n\tk = one\\\n two # C:\\Users\n' > config ;;
        1) printf '%s' $'[a]\n\tk = one\\\n two ; C:\\Users\n' > config ;;
        2) printf '%s' $'[a]\n\tk = one\\\n two\\tthree # C:\\Users\n' > config ;;
        3) printf '%s' $'[a]\n\tk = one\\\n "two # three" # C:\\Users\n' > config ;;
        4) printf '%s' $'[a]\n\tk = value \\' > config ;;
        5) printf '%s' $'[a]\n\tk = value \\\n' > config ;;
        6) printf '%s' $'[a]\n\tk = value \t\\\n' > config ;;
        7) printf '%s' $'[a]\n\tk = one\\\n two \\\n' > config ;;
        8) printf '%s' $'[a]\n\tk = C:\\Users \\\n' > config ;;
        9) printf '%s' $'[a]\n\tk = val\\\\\n next\n' > config ;;
        *) exit 1 ;;
    esac
    cp config baseline
    ;;
unquoted-escapes)
    while IFS= read -r line; do
        if [ "$line" = '[custom]' ]; then continue; fi
        key=${line%% =*}
        key=${key#  }
        printf '%s\n' '[custom]' "$line" > "$key"
    done < "$2"
    ;;
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
