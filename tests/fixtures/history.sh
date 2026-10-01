#!/usr/bin/env bash
set -eu

source=$1
source_revision=$2
revision=$3
layout=$4

if test "$layout" = remote; then
    port=$5
    git clone --shared --bare "$source" remote
    git -C remote symbolic-ref HEAD refs/heads/master
    git -C remote update-ref refs/heads/master "$source_revision"
    touch remote/git-daemon-export-ok
    git -C remote config daemon.receivepack true
    git clone --shared --no-checkout remote repo
    git -C repo checkout -B master "$revision"
    git -C repo remote set-url origin ../remote
    git -C repo remote add daemon_origin ../remote
    git -C repo fetch daemon_origin
    git -C repo remote set-url daemon_origin "git://localhost:$port/remote"
else
    set --
    if test "$layout" = bare; then set -- --bare; fi
    git clone --shared --no-checkout "$@" "$source" repo
    git -C repo symbolic-ref HEAD refs/heads/master
    git -C repo update-ref -m 'Create test branch' refs/heads/master "$revision"
    if test "$layout" != bare; then git -C repo checkout --force master; fi

    if test "$layout" = baseline; then
        test -n "$(git -C repo tag --list '[0-9]*' 'v[0-9]*')"
        git -C repo tag -f __testing_point__ "$source_revision"
        for _ in 1 2 3; do git -C repo reset --hard HEAD~1; done
        git -C repo reset --hard "$source_revision"
    fi
fi
