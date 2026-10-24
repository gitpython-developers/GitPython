#!/usr/bin/env bash
set -eu

case "$1" in
    version)
        # Supply both launcher formats so the selected interpreter chooses its native one.
        printf '#!/bin/sh\necho '\''git version %s (fake)'\''\n' "$2" > fake-git
        chmod +x fake-git
        printf '@echo git version %s (fake)\r\n' "$2" > fake-git.cmd
        ;;
    impostor)
        git init --initial-branch=master repo
        cd repo
        if test "$2" = win32; then
            cp "$(cygpath -u "$3")/system32/hostname.exe" git.exe
            if test "$4" = True; then cp git.exe cmd.exe; fi
        else
            printf '#!/bin/sh\n' > git
            chmod +x git
            if test "$4" = True; then cp git sh; fi
        fi
        ;;
    environment)
        printf '#!/usr/bin/env sh\necho FOO\n' > failing-script.sh
        chmod +x failing-script.sh
        git init --initial-branch=master repo
        git -C repo remote add ssh-origin ssh://git@server/foo
        ;;
esac
