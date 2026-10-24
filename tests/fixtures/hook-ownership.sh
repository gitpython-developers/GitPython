#!/usr/bin/env bash
set -eu

case "$1" in
    bare)
        git init --bare --initial-branch=master repo
        hooks=repo/hooks
        ;;
    linked)
        git init --initial-branch=master main
        git -C main -c commit.gpgsign=false commit --allow-empty -m initial
        git -C main worktree add -b linked ../repo
        hooks=main/.git/hooks
        ;;
    separate)
        git init --initial-branch=master --separate-git-dir=metadata repo
        printf 'gitdir: ../metadata\n' >repo/.git
        hooks=metadata/hooks
        ;;
    configured)
        git init --initial-branch=master repo
        git -C repo config core.worktree ../repo
        mv repo/.git metadata
        hooks=metadata/hooks
        ;;
    regular)
        git init --initial-branch=master repo
        hooks=repo/.git/hooks
        ;;
    *) exit 1 ;;
esac
printf "#!/usr/bin/env sh\necho 'ran hook' >output.txt\n" >"$hooks/pre-commit"
chmod +x "$hooks/pre-commit"
