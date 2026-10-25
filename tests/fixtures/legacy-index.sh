#!/usr/bin/env bash
set -eu
git init --initial-branch=main repo
cd repo
original=$(printf '// vers\343o original\n' | git hash-object -w --stdin)
printf '100644 %s\tfonte-\365.pas\0' "$original" | git update-index -z --index-info
git commit -m initial
staged=$(printf '// vers\343o nova\n' | git hash-object -w --stdin)
printf '100644 %s\tfonte-\365.pas\0' "$staged" | git update-index -z --index-info
