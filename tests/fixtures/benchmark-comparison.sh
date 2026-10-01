#!/usr/bin/env bash
set -eu
for name in cli gix; do
    backend=$name
    fixture_revision=fixture
    result_digest=equal
    cli_processes=0
    if test "$name" = gix; then
        case "$1" in
        backend) backend=different ;;
        fixture_revision) fixture_revision=different ;;
        result_digest) result_digest=different ;;
        cli_processes) cli_processes=1 ;;
        equal) ;;
        *) exit 1 ;;
        esac
    fi
    cat > "$name.json" <<EOF
{
  "version": "1.0",
  "benchmarks": [{"runs": [{"values": [0.1, 0.2]}]}],
  "metadata": {
    "gitpython_revision": "source", "fixture_revision": "$fixture_revision",
    "fixture_tree": "tree", "fixture_status": "clean", "fixture_object_format": "sha1",
    "fixture_ref_format": "files", "git_version": "git version 2.52.0",
    "python_version": "3.12.14", "result_digest": "$result_digest", "backend_decisions": "[]",
    "cli_processes": $cli_processes, "name": "journey", "backend": "$backend"
  }
}
EOF
done
printf '{"fixture_revision":"fixture","max_gix_cli_processes":{"journey":0}}' > budget.json
printf '{"fixture_revision":"fixture","max_gix_cli_processes":{"journey":1}}' > relaxed-budget.json
