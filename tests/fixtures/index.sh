#!/usr/bin/env bash
set -eu

scenario=$1
shift
case "$scenario" in
    pathspec-rejected) printf 'unmatched-path-one\nunmatched-path-two' >pathspecs; exit ;;
    pathspec-allowed) printf 'CHANGES\0' >pathspecs; exit ;;
    file-swap) printf 'some data' >foo; exit ;;
esac

case "$scenario" in
    hook-run|hook-success|hook-fail|msg-success|msg-fail|bare-add)
        git init --bare --initial-branch=master repo
        tree=$(git -C repo mktree </dev/null)
        commit=$(printf initial | git -C repo commit-tree "$tree")
        git -C repo update-ref refs/heads/master "$commit"
        hooks=repo/hooks
        ;;
    *) git init --initial-branch=master repo; hooks=repo/.git/hooks ;;
esac

case "$scenario" in
    empty) ;;
    null-tree) printf '# Initial file\n' >repo/.gitkeep; git -C repo add .gitkeep ;;
    file) printf %s "$2" >"repo/$1" ;;
    index-before) git -C repo update-index --add --cacheinfo 100644,6161616161616161616161616161616161616161,before ;;
    bare-add) printf 'This is a BytesIO file' | git -C repo hash-object -w --stdin >blob-id ;;
    unsafe-tree)
        blob=$(printf data | git -C repo hash-object -w --stdin)
        escaped=$(printf %s "$blob" | sed 's/../\\x&/g')
        { printf '100755 %s\0' "$1"; printf %b "$escaped"; } |
            git -C repo hash-object -w -t tree --literally --stdin >tree-id
        ;;
    directory-symlink)
        gix_testtools_require_symlinks
        target=repo/target
        link=target
        if test "$1" = True; then target=target; link=../target; fi
        mkdir "$target"
        printf 'private data' >"$target/secret"
        ln -s "$link" repo/link
        ;;
    gitmodules-link)
        source=.gitmodules
        if test "$2" = True; then source=safe-link; fi
        if test "$1" = stored-entry; then
            printf target | git -C repo hash-object -w --stdin >blob-id
        else
            gix_testtools_require_symlinks
            ln -s target "repo/$source"
        fi
        ;;
    root-symlink)
        gix_testtools_require_symlinks
        mkdir outside
        printf contents >repo/file
        ln -s ../outside repo/link
        ;;
    unicode-symlink) gix_testtools_require_symlinks; ln -s ../café repo/link ;;
    colon) mkdir -p repo/nested/a:b; printf contents >repo/nested/a:b/file ;;
    fifo) mkfifo repo/fifo ;;
    hook-run) printf "#!/usr/bin/env sh\necho 'ran hook' >output.txt\n" >"$hooks/pre-commit" ;;
    hook-success) printf '#!/usr/bin/env sh\nexit 0\n' >"$hooks/pre-commit" ;;
    hook-fail|msg-fail)
        name=pre-commit
        if test "$scenario" = msg-fail; then name='commit-msg'; fi
        printf '#!/usr/bin/env sh\necho stdout; echo stderr 1>&2; exit 1\n' >"$hooks/$name"
        ;;
    msg-success)
        # The generated hook expands its own arguments.
        # shellcheck disable=SC2016
        printf '#!/usr/bin/env sh\nprintf " from commit-msg" >> "$1"\n' >"$hooks/commit-msg"
        ;;
    custom-hook)
        mkdir repo/custom-hooks
        printf "#!/usr/bin/env sh\necho 'ran custom hook' >custom-hook-output.txt\n" >repo/custom-hooks/pre-commit
        chmod +x repo/custom-hooks/pre-commit
        git -C repo config core.hooksPath custom-hooks
        ;;
    outside-hook)
        mkdir hooks
        printf "#!/usr/bin/env sh\necho 'ran outside hook' >outside-hook-output.txt\n" >hooks/pre-commit
        chmod +x hooks/pre-commit
        git -C repo config core.hooksPath "$PWD/hooks"
        ;;
    hook-impostor)
        python=$1
        platform=$2
        inputs=$3
        "$python" -m venv --without-pip repo
        if test "$platform" = win32; then
            cp repo/Scripts/python.exe repo/bash.exe
        else
            cp repo/bin/python repo/sh
        fi
        cp "$inputs/polyglot" "$hooks/pre-commit"
        ;;
    extended-index)
        printf hello >repo/file.txt
        printf world >repo/file2.txt
        git -C repo add --intent-to-add file.txt
        ;;
    checkout)
        mkdir repo/nested
        printf first >repo/nested/first
        printf second >repo/nested/second
        printf outside >repo/outside
        git -C repo add nested outside
        rm repo/nested/first
        if test "$1" = True; then rm repo/nested/second; fi
        ;;
    checkout-records)
        mkdir repo/nested
        printf nested >repo/nested/$'first\noutside'
        printf committed >repo/outside
        printf quoted >'repo/"quoted"'
        git -C repo add nested outside '"quoted"'
        rm repo/nested/$'first\noutside' 'repo/"quoted"'
        printf local >repo/outside
        ;;
    *) printf 'Unknown index fixture: %s\n' "$scenario" >&2; exit 1 ;;
esac
for hook in "$hooks/pre-commit" "$hooks/commit-msg"; do
    if test -f "$hook"; then chmod +x "$hook"; fi
done
