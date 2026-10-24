#!/usr/bin/env bash
set -eu

case "$1" in
    lock) mkdir -p "$(dirname "$2")" ;;
    blocking)
        mkdir directory
        case "$2" in
            empty) : ;;
            contended) : > directory/resource.lock ;;
            unwritable) chmod 500 directory ;;
            *) exit 1 ;;
        esac
        ;;
    symlink)
        if test "$2" = True; then
            printf 'Do not modify the symlink target.' > outside-the-lock
        fi
        ln -s outside-the-lock my-lock-file.lock
        ;;
esac
