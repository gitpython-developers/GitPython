#!/usr/bin/env bash
set -eu
scenario=$1
if test "$scenario" = bare; then
    git init -q --bare --object-format="$2" --ref-format="$3" repo
    exit 0
fi
git init -q --object-format="$2" --ref-format="$3" repo
cd repo
case "$scenario" in
objects_index_commit_and_merge)
    mkdir dir
    for name in 'space name' --option unicode-é dir/file; do printf '%s' "$name" > "$name"; done
    case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *)
        for name in $'line\nname' $'tab\tname'; do printf '%s' "$name" > "$name"; done ;;
    esac
    ;;
index_flags_are_preserved_until_path_is_staged)
    touch intent
    printf skip > skip
    git add -N -- intent
    git add -- skip
    git update-index --skip-worktree -- skip
    ;;
commit_hooks_use_git_and_keep_their_index_changes)
    printf before > file
    git add file
    mkdir -p .git/hooks
    printf '#!/bin/sh\nprintf after >file\ngit add -- file\n' > .git/hooks/pre-commit
    # The generated hook expands its own arguments.
    # shellcheck disable=SC2016
    printf '#!/bin/sh\nprintf " hook" >>"$1"\n' > .git/hooks/commit-msg
    chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
    ;;
git_index_storage_variants)
    mkdir inside outside
    printf inside/file > inside/file
    printf outside/file > outside/file
    git add inside outside
    git commit -qm initial
    case "$4" in
    v4) git update-index --index-version=4 ;;
    split) git update-index --split-index ;;
    sparse) git sparse-checkout init --cone --sparse-index; git sparse-checkout set inside ;;
    esac
    ;;
trailer_commands_are_not_executed)
    git config trailer.custom.cmd 'touch executed'
    ;;
pending_index_queries_removal_and_failed_update)
    printf old > file
    git add file
    ;;
malformed_index_failure_is_propagated)
    printf 'not an index' > .git/index
    ;;
failed_hook_retains_index_edit_without_advancing_head)
    printf old > file
    git add file
    git commit -qm initial
    printf '#!/bin/sh\nprintf changed > file\ngit add file\nexit 1\n' > .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    ;;
commit_and_tag_metadata_preserves_encoding_signature_and_message)
    tree=$(git mktree </dev/null)
    {
        printf 'tree %s\n' "$tree"
        printf 'author M\351 <name@example.invalid> 1112911991 -0200\n'
        printf 'committer M\351 <name@example.invalid> 1112911991 -0200\n'
        printf 'encoding ISO-8859-1\nmergetag object %s\n type tree\n tag merged\n' "$tree"
        printf 'gpgsig fake signature\n continuation\n\n\nexact caf\351\n\n'
    } | git hash-object -w -t commit --stdin > ../commit-id
    commit=$(cat ../commit-id)
    {
        printf 'object %s\ntype commit\ntag arbitrary\n' "$commit"
        printf 'tagger Tagger <tag@example.invalid> 1112911991 +0200\n\n\nmessage\n\n'
    } | git hash-object -w -t tag --stdin > ../tag-id
    ;;
tree_names_do_not_require_worktree_support|index_stages_missing_objects_and_atomic_failure|revision_injection_cannot_write_or_checkout) ;;
*) exit 1 ;;
esac
