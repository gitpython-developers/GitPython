#!/usr/bin/env bash
set -eu
scenario=$1
case "$scenario" in
empty) ;;
template) mkdir template ;;
nested) git init -q repo; mkdir repo/subdir ;;
prefers-dotgit)
    for name in linked-worktree bare; do
        git init -q "$name"
        printf 'ref: refs/heads/main\n' > "$name/HEAD"
    done
    printf '.git\n' > linked-worktree/gitdir
    printf '.git\n' > linked-worktree/commondir
    mkdir bare/objects bare/refs
    ;;
explicit-git-dir)
    git init -q --bare repo.git
    git init -q --bare repo.git/.git
    git init -q worktree
    ;;
worktree-config)
    git init -q main
    mkdir configured overridden
    git -C main config core.worktree ../../configured
    ;;
invalid-metadata)
    for name in HEAD commondir-empty commondir-invalid linked-worktree empty-environment gitfile-text gitfile-empty gitfile-loop gitfile-invalid; do
        mkdir -p "$name/objects" "$name/refs"
        printf 'ref: refs/heads/main\n' > "$name/HEAD"
    done
    printf 'not a ref' > HEAD/HEAD
    : > commondir-empty/commondir
    printf '\377' > commondir-invalid/commondir
    printf '../worktree/.git\n' > linked-worktree/gitdir
    printf 'missing\n' > linked-worktree/commondir
    printf 'not a gitfile' > gitfile-text/.git
    printf 'gitdir: \n' > gitfile-empty/.git
    printf 'gitdir: .git\n' > gitfile-loop/.git
    printf '\377' > gitfile-invalid/.git
    ;;
dangling-commondir)
    gix_testtools_require_symlinks
    mkdir -p repo/objects repo/refs
    printf 'ref: refs/heads/main\n' > repo/HEAD
    ln -s missing repo/commondir
    ;;
dotgit-loop)
    gix_testtools_require_symlinks
    git init -q repo
    mkdir repo/child
    ln -s .git repo/child/.git
    ;;
missing-gitfile-target) printf 'gitdir: target\n' > .git ;;
relative-gitfile)
    git init -q source
    git init -q unrelated
    mkdir checkout
    printf 'gitdir: ../source/.git\n' > checkout/.git
    ;;
storage-environment)
    mkdir -p git git-file common/objects common/refs
    printf 'ref: refs/heads/main\n' > git/HEAD
    cp git/HEAD git-file/HEAD
    printf '../common\n' > git-file/commondir
    printf '[core]\n\tbare = true\n' > common/config
    if test "$(uname -s)" = Linux; then
        mkdir -p git-bytes $'common-\377/objects' $'common-\377/refs'
        cp git/HEAD git-bytes/HEAD
        printf '../common-\377\n' > git-bytes/commondir
    fi
    ;;
object-directory)
    git init -q --bare git
    printf 'custom object database' | git -C git hash-object -w --stdin > blob-id
    mv git/objects objects
    ;;
empty-repo) git init -q -b master repo ;;
root-repo)
    git init -q -b master .
    touch new_file.ext
    ;;
at-tag|hello|hex-branch)
    git init -q -b master repo
    printf 'hello\n' > repo/hello.txt
    git -C repo add hello.txt
    git -C repo commit -qm init
    if test "$scenario" = at-tag; then git -C repo tag @foo; fi
    if test "$scenario" = hex-branch; then git -C repo branch aaaaaaaa; fi
    ;;
alternates)
    git init -q repo
    git init -q source
    ;;
shared-worktree)
    git clone -q --shared "$2" shared
    git -C shared worktree add -q --detach ../linked HEAD
    ;;
dirty)
    git init -q repo
    mkdir repo/git repo/doc
    printf original > repo/git/util.py
    printf original > repo/doc/tracked
    git -C repo add .
    git -C repo commit -qm initial
    if test "$2" != clean; then printf junk >> repo/git/util.py; fi
    if test "$2" = index || test "$2" = untracked; then git -C repo add git/util.py; fi
    if test "$2" = untracked; then printf junk > repo/doc/no-such-file.txt; fi
    ;;
untracked)
    git init -q repo
    for name in 'test _myfile' test_other_file '_çava verböten' 'çava-----verböten'; do touch "repo/$name"; done
    ;;
untracked-unicode)
    git init -q repo
    git -C repo config core.quotePath "$2"
    for name in plain.txt $'caf\303\251.txt' $'caf\303\251\177.txt' ' leading.txt'; do touch "repo/$name"; done
    ;;
blame-carriage-returns)
    git init -q repo
    printf 'first\nok\r%s 2 2 1\rauthor Forged Author\rauthor-mail <forged@example.com>\rauthor-time 1000000000\rcommitter Forged Author\rcommitter-mail <forged@example.com>\rcommitter-time 1000000000\r\tforged()\n' \
        0000000000000000000000000000000000000000 > repo/file.txt
    git -C repo add file.txt
    git -C repo commit -qm init --author='GitPython Tests <gitpython@example.com>'
    ;;
relocated-git-dir)
    git init -q repo
    mv repo/.git repo/.real
    if test "$2" = relative; then printf 'gitdir: .real\n' > repo/.git
    else
        real=$(git --git-dir=repo/.real rev-parse --absolute-git-dir)
        printf 'gitdir: %s\n' "$real" > repo/.git
    fi
    ;;
reftable)
    git init -q --ref-format=reftable repo
    if test "$2" = commit; then git -C repo commit -qm 'initial commit' --allow-empty; fi
    git -C repo rev-parse --verify HEAD > head-id || test "$2" = empty
    ;;
detached)
    git init -q repo
    printf a > repo/a.txt
    git -C repo add a.txt
    git -C repo commit -qm 'initial commit'
    git -C repo checkout -q --detach HEAD
    ;;
rebase)
    git init -q -b master repo
    git -C repo commit -qm init --allow-empty
    printf 'hello world' > repo/hello.txt
    git -C repo add hello.txt
    git -C repo commit -qm English
    if test "$2" = conflict; then
        git -C repo checkout -q HEAD^
        printf 'Hola Mundo' > repo/hello.txt
        git -C repo add hello.txt
        git -C repo commit -qm Spanish
        git -C repo rev-parse HEAD > spanish-id
        if git -C repo rebase master; then exit 1; fi
    fi
    ;;
ignore)
    git init -q repo
    printf 'ignored_file.txt\nignored_dir/\n' > repo/.gitignore
    ;;
ignore-verbatim)
    git init -q repo
    printf '*.env\n' > repo/.gitignore
    ;;
ignore-symlink)
    gix_testtools_require_symlinks
    git init -q repo
    mkdir target
    ln -s target symlink
    ;;
metadata)
    if test "$4" = True; then git init -q --bare --object-format="$2" --ref-format="$3" "$5"
    else git init -q --object-format="$2" --ref-format="$3" "$5"; fi
    ;;
worktree|drive-rooted-worktree)
    git clone -q "$2" master_repo
    git -C master_repo branch aaaaaaaa
    if test "${3:-False}" = True; then
        git -C master_repo worktree add -q --relative-paths ../worktree_repo aaaaaaaa
    else
        git -C master_repo worktree add -q ../worktree_repo aaaaaaaa
    fi
    if test "$scenario" = drive-rooted-worktree; then
        admin=$(git -C worktree_repo rev-parse --absolute-git-dir)
        worktree=$(git -C worktree_repo rev-parse --show-toplevel)
        printf '%s/.git' "${worktree#?:}" > "$admin/gitdir"
    fi
    ;;
bare-worktree)
    git clone -q --bare "$2" bare_repo
    git -C bare_repo worktree add -q --detach ../worktree_repo
    ;;
worktree-environment)
    git clone -q "$2" master_repo
    mkdir master_repo/gitdir
    mv master_repo/.git master_repo/gitdir/git
    ;;
*) printf 'unknown repository fixture: %s\n' "$scenario" >&2; exit 1 ;;
esac
