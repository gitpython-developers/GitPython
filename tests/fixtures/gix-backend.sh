#!/usr/bin/env bash
set -eu
scenario=$1
hash=$2
extra=$3
if test "$scenario" = scratch; then exit 0; fi
case "$scenario" in
metadata_symlinks_retain_git_canonicalization|native_commit_statistics_match_cli)
    gix_testtools_require_symlinks ;;
gitfile_reopens_canonical_native_repository)
    if test "$extra" = alias/.git; then gix_testtools_require_symlinks; fi ;;
esac
git init -q -b main --object-format="$hash" repo
case "$scenario" in
reftable_head_reports_unsupported_storage)
    git init -q --object-format="$hash" --ref-format=reftable reftable
    ;;
native_head_does_not_validate_repository_extensions)
    git init -q --object-format="$hash" unknown
    git -C unknown config core.repositoryFormatVersion 1
    git -C unknown config extensions.unknown true
    ;;
native_worktree_inventory_includes_bare_main)
    git init -q --bare --object-format="$hash" bare
    git -C bare worktree add -q --orphan -b linked ../linked
    git -C bare worktree lock --reason keep ../linked
    ;;
native_repository_lifetime_and_refresh)
    printf payload > repo/file
    printf '[test]\nvalue = first\n' > included
    ;;
opening_and_discovery_use_gix_with_explicit_fallbacks|native_metadata_paths_match_git_in_each_worktree)
    git -C repo commit -qm initial --allow-empty
    mkdir -p repo/nested/directory
    git -C repo worktree add -q --detach ../linked
    git init -q --bare --object-format="$hash" bare
    git -C bare worktree add -q --orphan -b main ../bare-linked
    printf 'gitdir: repo/.git\n' > gitfile
    ;;
gitfile_reopens_canonical_native_repository)
    if test "$extra" = alias/.git; then ln -s repo alias; fi
    printf 'gitdir: %s\n' "$extra" > gitfile
    ;;
gitfile_reopen_failure_selects_fallback)
    printf 'gitdir: repo/.git\n' > gitfile
    ;;
native_objects_trees_commits_and_index_reads)
    mkdir repo/dir
    for name in file 'dir/with space' dir/unicode-é --option; do printf '%s' "$name" > "repo/$name"; done
    ;;
metadata_symlinks_retain_git_canonicalization)
    ln -s ../../modules repo/.git/modules
    ln -s ../../COMMIT_EDITMSG repo/.git/COMMIT_EDITMSG
    ;;
native_tree_and_commit_bytes_match_cli)
    printf 'payload\n' > repo/file
    ;;
hooks_retain_cli_even_when_missing)
    git -C repo commit -qm initial --allow-empty
    git -C repo worktree add -q --detach ../linked
    ;;
native_submodule_inventory_and_cached_fields_match_cli)
    git -C repo commit -qm initial --allow-empty
    first=$(git -C repo rev-parse HEAD)
    cat > repo/.gitmodules <<'EOF'
[submodule "z-last"]
path = z
url = ../source z
[submodule "a.first"]
path = a
url = ../old
url = ../source-a
branch = topic
EOF
    git -C repo add .gitmodules
    git -C repo update-index --add --cacheinfo "160000,$first,z" --cacheinfo "160000,$first,a"
    git -C repo commit -qm modules
    case "$extra" in
    duplicate)
        cp repo/.gitmodules modules-original
        { printf '[submodule "a.first"]\n'; cat modules-original; } > repo/.gitmodules
        rm modules-original
        ;;
    include) printf '[include]\npath = not-read\n' >> repo/.gitmodules ;;
    esac
    ;;
native_revision_path_and_mode_match_cli)
    cd repo
    blob=$(printf data | git hash-object -w --stdin)
    git update-index --add --cacheinfo "100644,$blob,dir/file" --cacheinfo "100755,$blob,executable" --cacheinfo "120000,$blob,link"
    git commit -qm paths
    GIT_INDEX_FILE="$PWD/../alternate-index" git update-index --add --cacheinfo "100755,$blob,alternate"
    ;;
native_reference_reads_include_missing_and_dangling_targets)
    git -C repo commit -qm initial --allow-empty
    git -C repo pack-refs --all --prune
    git -C repo symbolic-ref refs/heads/alias refs/heads/absent
    ;;
native_command_queries_match_cli)
    printf content > repo/file
    git -C repo add file
    git -C repo commit -qm initial
    git -C repo config test.value configured
    ;;
reference_enumeration_preserves_aliases_and_skips_dangling_refs)
    git -C repo commit -qm initial --allow-empty
    git -C repo symbolic-ref refs/heads/alias refs/heads/main
    if test "$extra" = dangling; then git -C repo symbolic-ref refs/heads/dangling refs/heads/missing; fi
    ;;
tree_writes_validate_child_object_kinds|branch_blob_updates_match_git)
    git -C repo commit -qm initial --allow-empty
    printf x | git -C repo hash-object -w --stdin > blob-id
    git -C repo symbolic-ref refs/aliases/main refs/heads/main
    ;;
partial_native_stream_does_not_corrupt_next_read)
    printf abcdef | git -C repo hash-object -w --stdin > blob-ids
    printf xyz | git -C repo hash-object -w --stdin >> blob-ids
    ;;
native_history_and_references|reflog_message_cleanup_uses_cli_before_mutation)
    export GIT_COMMITTER_NAME="Reflog Actor" GIT_COMMITTER_EMAIL=actor@example.invalid GIT_COMMITTER_DATE="1100000000 -0430"
    git -C repo commit -qm first --allow-empty
    first=$(git -C repo rev-parse HEAD)
    tree=$(git -C repo rev-parse 'HEAD^{tree}')
    printf second | git -C repo commit-tree "$tree" -p "$first" > second-id
    git -C repo branch other "$first"
    git -C repo branch control "$first"
    ;;
native_refedit_message_is_verbatim)
    git -C repo commit -qm initial --allow-empty
    ;;
native_raw_diff_matches_cli)
    cd repo
    mkdir dir
    printf 'rename me\n' > a
    printf 'old\n' > dir/b
    printf 'gone\n' > removed
    git add .
    git commit -qm before
    mv a z
    printf 'changed\n' > dir/b
    git add --all
    git commit -qm after
    ;;
native_status_and_ignore_match_cli_without_writing_index)
    cd repo
    printf '*.log\nignored/\n' > .gitignore
    printf 'tracked even though ignored\n' > tracked.log
    git add .gitignore
    git add -f tracked.log
    git commit -qm initial
    mkdir ignored
    printf ignored > ignored/file
    printf untracked > "$extra"
    printf changed > tracked.log
    git init -q nested
    ;;
native_status_tracks_submodule_dirtiness)
    git init -q --object-format="$hash" source
    printf initial > source/file
    git -C source add file
    git -C source commit -qm initial
    git -C repo -c protocol.file.allow=always submodule add -q ../source module
    git -C repo commit -qm 'add submodule'
    printf modified > repo/module/file
    ;;
native_commit_statistics_match_cli)
    cd repo
    git config diff.algorithm myers
    printf 'one\ntwo\n' > file
    printf 'a\0b' > binary
    printf 'gone\n' > old
    printf text > "link"
    git add .
    git commit -qm first
    printf 'two\nthree\nfour\n' > file
    printf 'b\0c' > binary
    mv old new
    rm link
    ln -s file link
    git add --all
    git commit -qm second
    git commit -qm empty --allow-empty
    if test "$extra" = True; then printf 'file -diff\n' > .gitattributes; fi
    ;;
unknown_command_and_storage_environment_use_cli|compatibility_object_format_uses_cli_before_writing|per_command_committer_identity_uses_cli|a_native_write_failure_is_not_retried|commit_identity_cleanup_matches_git) ;;
*) printf 'unknown scenario: %s\n' "$scenario" >&2; exit 1 ;;
esac
