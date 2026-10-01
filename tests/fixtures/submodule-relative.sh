#!/usr/bin/env bash
set -eu
git() { command git -c protocol.file.allow=always "$@"; }
scenario=$1
root=$PWD
git init -q -b master parent
case "$scenario" in
    add)
        state=$2
        remote=$3
        if test "$state" != unborn; then git -C parent commit --allow-empty -qm initial; fi
        if test "$state" = detached; then git -C parent checkout -q --detach; fi
        base=parent
        if test "$remote" = origin; then base=remote; fi
        if test "$remote" != None; then
            url=.
            if test "$remote" = origin; then url="$root/$base"; fi
            git -C parent remote add origin "$url"
        fi
        git init -q -b master "$base/source"
        git -C "$base/source" commit --allow-empty -qm initial
        printf '%s' "$base/source" >source-path
        ;;
    cygwin)
        git init -q -b master source
        git -C source commit --allow-empty -qm initial
        ;;
    local-remote)
        git init -q -b master repos/child.git
        git -C repos/child.git commit --allow-empty -qm initial
        git -C parent remote add origin ../repos/super.git
        git -C parent config branch.master.remote origin
        git -C parent config branch.master.merge refs/heads/master
        ;;
    root-anchor|root-single)
        source=source
        replacement=replacement
        remote=../super.git
        old=../../lib.git
        if test "$scenario" = root-anchor; then
            source=repos/source.git
            replacement=repos/replacement.git
            remote=../repos/super.git
            old=../source.git
        fi
        git init -q -b master "$source"
        git -C "$source" commit --allow-empty -qm initial
        git clone -q "$source" "$replacement"
        git -C parent remote add origin "$remote"
        git -C parent submodule add "$root/$source" module
        git -C parent config -f .gitmodules submodule.module.url "$old"
        git -C parent add .gitmodules module
        git -C parent commit -qm 'Record historical URL'
        git -C parent rev-parse HEAD >previous
        url="$root/$replacement"
        if test "$scenario" = root-anchor; then url=../replacement.git; fi
        git -C parent config -f .gitmodules submodule.module.url "$url"
        git -C parent add .gitmodules
        git -C parent commit -qm 'Change URL'
        printf '%s' "$replacement" >replacement-path
        ;;
    root-matches)
        git init -q -b master source
        git -C source commit --allow-empty -qm initial
        git -C parent submodule add "$root/source" module
        git -C parent config -f .gitmodules submodule.module.url ../source
        git -C parent add .gitmodules module
        git -C parent commit -qm 'Record relative URL'
        git -C parent rev-parse HEAD >previous
        git -C parent config -f .gitmodules submodule.module.url "$root/source"
        git -C parent add .gitmodules
        git -C parent commit -qm 'Use existing remote URL'
        ;;
    update-remote)
        git -C parent remote add origin ssh://git@host/org/super.git
        mkdir parent/planted
        ;;
    tracking-remote)
        git -C parent commit --allow-empty -qm initial
        git -C parent remote add origin git@host:other/super.git
        ;;
esac
