#!/usr/bin/env bash
set -eu
scenario=$1
if test "$scenario" = scratch; then exit 0; fi
git init -q --object-format="$2" --ref-format="$3" repo
cd repo
case "$scenario" in
empty|default_database_never_uses_python_storage) ;;
tag_storage_rejects_missing_tagger)
    blob=$(printf x | git hash-object -w --stdin)
    printf 'object %s\ntype blob\ntag invalid\n\nmessage\n' "$blob" > ../invalid-tag
    git hash-object -t tag --literally --stdin < ../invalid-tag > ../invalid-tag-id
    ;;
batch_queries_cannot_inject_a_second_request)
    printf 'contents\0\n' | git hash-object -w --stdin > ../blob-id
    ;;
blame_and_archive_do_not_run_configured_commands)
    printf '#!/bin/sh\nprintf executed > executed\ncat\n' > unexpected-command
    chmod +x unexpected-command
    printf 'original\n' > file
    printf 'file diff=unexpected\n' > .gitattributes
    git add file .gitattributes
    git commit -qm initial
    git config diff.unexpected.textconv 'sh ./unexpected-command'
    for name in custom tgz tar.gz; do git config "tar.$name.command" 'sh ./unexpected-command'; done
    ;;
*) exit 1 ;;
esac
