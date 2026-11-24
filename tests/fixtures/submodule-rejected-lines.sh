#!/usr/bin/env bash
set -eu
git init -q -b main --object-format="$1" repo
{
    printf '[submodule "module"]\npath = module\nurl = ../base\n'
    case "$2" in
    implicit-extra) printf 'x url = ../other\n' ;;
    inline-extra) printf '[submodule "module"] x url = ../other\n' ;;
    comment-in-key) printf 'br#anch = main\n' ;;
    *) exit 1 ;;
    esac
} >repo/.gitmodules
