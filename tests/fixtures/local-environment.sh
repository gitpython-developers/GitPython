#!/usr/bin/env bash
set -eu

source=$1
platform=$2
cat >gitconfig <<'EOF'
[user]
name = GitPython Tests
email = tests@example.invalid
EOF
if test "$platform" = win32; then
    printf '[core]\nautocrlf = true\n' >>gitconfig
fi
cat "$source/test/fixtures/.gitconfig" >>gitconfig
