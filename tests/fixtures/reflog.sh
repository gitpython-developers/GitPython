#!/usr/bin/env bash
set -eu
scenario=$1
git init -q --object-format="$2" --ref-format="$3" repo
cd repo
export GIT_AUTHOR_NAME='Commit Author' GIT_AUTHOR_EMAIL=author@example.invalid
export GIT_COMMITTER_NAME='First Committer' GIT_COMMITTER_EMAIL=first@example.invalid
export GIT_AUTHOR_DATE='1000000000 +0000' GIT_COMMITTER_DATE='1000000001 +0130'
git commit -qm initial --allow-empty
case "$scenario" in
reference_transactions_and_discovery)
    git worktree add -q --detach ../linked HEAD
    ;;
tag_creation_requires_signing_opt_in)
    printf '#!/bin/sh\ntouch signed\nexit 1\n' > signer
    chmod +x signer
    git config gpg.program ./signer
    git config tag.gpgSign true
    ;;
esac
