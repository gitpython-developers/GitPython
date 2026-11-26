#!/usr/bin/env bash
set -eu

git init --initial-branch=main --object-format="${2:-sha1}" --ref-format="${3:-files}" source
git -C source commit --allow-empty -m first
case "$1" in
    push-mirror)
        git clone --bare source mirror
        git -C source commit --allow-empty -m second
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C clone remote add mirror ../mirror
        git -C clone fetch mirror
        git -C clone config branch.main.pushRemote mirror
        git -C clone config remote.mirror.mirror true
        git -C clone config push.default upstream
        ;;
    fetch)
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C source commit --allow-empty -m second
        ;;
    tag-named-like-branch)
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C source commit --allow-empty -m second
        git -C source tag refs/heads/main
        ;;
    abbreviated-tag-source)
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C clone tag refs/archive/v1
        git -C source commit --allow-empty -m second
        git -C source tag v1
        ;;
    notes-and-tag-wildcards)
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C clone config --unset-all remote.origin.fetch
        git -C clone config --add remote.origin.fetch '+refs/notes/*:refs/notes/*'
        git -C clone config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
        git -C source notes add -m 'a note'
        initial_notes=$(git -C source rev-parse refs/notes/commits)
        git -C source notes append -m 'more notes'
        git -C source update-ref refs/fixture/updated-notes refs/notes/commits
        git -C source update-ref refs/notes/commits "$initial_notes"
        ;;
    prefetch)
        git -C source branch second
        git clone source clone
        git -C clone remote set-url origin ../source
        git -C clone fetch --prefetch
        ;;
    quoted)
        git init --initial-branch=main parent
        ;;
esac
