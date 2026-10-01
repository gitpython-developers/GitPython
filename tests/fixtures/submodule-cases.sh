#!/usr/bin/env bash
set -eu
export MSYS="${MSYS:-} winsymlinks:nativestrict"
export GIT_AUTHOR_NAME='GitPython Tests' GIT_AUTHOR_EMAIL='tests@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000'
export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
git() { command git -c protocol.file.allow=always "$@"; }
scenario=$1
source=$2
root=$PWD
git init -q -b master parent
add_module() {
    git -C parent submodule add --name "$1" "$source" "$2"
    git -C parent commit -qm 'Add submodule'
}
case "$scenario" in
    deinit|deinit-latest|deinit-gitlink|deinit-nonempty|deinit-nested)
        git init -q -b master source
        printf '%s' 'submodule content' > source/file
        git -C source add file
        git -C source commit -qm 'Initial commit'
        source="$root/source"
        name=module
        path=module
        if test "$scenario" = deinit-nested; then name=nested/module; path=deps/module; fi
        add_module "$name" "$path"
        git -C parent submodule deinit --force "$path"
        case "$scenario" in
            deinit-latest|deinit-gitlink)
                touch source/new-file
                git -C source add new-file
                git -C source commit -qm 'Advance remote'
                if test "$scenario" = deinit-gitlink; then
                    git -C parent update-index --cacheinfo "160000,$(git -C source rev-parse HEAD),module"
                    git -C parent commit -qm 'Advance submodule'
                fi
                ;;
            deinit-nonempty) printf '%s' 'user content' > parent/module/file ;;
        esac
        ;;
    add-empty) git init -q -b master empty-repo ;;
    relative)
        git init -q -b master module
        git -C module commit --allow-empty -qm initial
        source=../module
        add_module module module
        git clone -q parent cloned_repo
        ;;
    invalid-name|invalid-name-existing|invalid-and-valid)
        git init -q -b master source
        git -C source commit --allow-empty -qm initial
        source="$root/source"
        if test "$scenario" != invalid-and-valid; then
            add_module module module
            git -C parent config -f .gitmodules --rename-section submodule.module submodule.../../../escaped/module
        else
            add_module invalid invalid
            add_module valid valid
            git -C parent config -f .gitmodules --rename-section submodule.invalid submodule.../invalid
        fi
        git -C parent add .gitmodules
        git -C parent commit -qm 'Change submodule name'
        git clone -q parent clone
        if test "$scenario" = invalid-name-existing; then
            mkdir escaped
            git clone -q --separate-git-dir="$root/escaped/module" source clone/module
        fi
        ;;
    module|list-valid|existing-repository)
        add_module module module
        if test "$scenario" = existing-repository; then
            git clone -q "$source" parent/existing-subrepository
        fi
        if test "$scenario" = list-valid; then
            rm -rf parent/module
            git -C parent add module
            git -C parent commit -qm 'Remove submodule checkout'
        fi
        ;;
    compatibility) add_module mymodules/myname submodules/intermediate/one ;;
    logical-name|remove-norefs)
        add_module mymodules/myname mymodules/myname
        if test "$scenario" = remove-norefs; then
            git -C parent/mymodules/myname remote add special git@server-shouldnotmatter:repo.git
        fi
        ;;
    branch-renames)
        git clone -q -b master "$source" sm-source
        source="$root/sm-source"
        git -C parent submodule add -b master --name mysubmodule "$source" subdir/submodule
        git -C parent commit -qm 'Add submodule'
        ;;
    non-submodule)
        mkdir parent/module
        printf 'test\n' > parent/module/a
        printf '[submodule "a"]\n    path = module\n    url = https://github.com/chaconinc/DbConnector\n' > parent/.gitmodules
        git -C parent add module/a .gitmodules
        git -C parent commit -qm test
        ;;
    include)
        printf 'not git config\n' > parent/secret
        printf '[submodule "module"]\n    path = module\n    url = https://example.com/module.git\n[include]\n    path = secret\n' > parent/.gitmodules
        ;;
    path-confined) mkdir parent/nested ;;
    checkout-link)
        mkdir parent/target
        ln -s target parent/link
        ;;
    literal-url)
        git init -q -b master "\$PATH_repo"
        printf content > "\$PATH_repo/file"
        git -C "\$PATH_repo" add file
        git -C "\$PATH_repo" commit -qm initial
        ;;
    rooted-gitfile)
        git init -q -b master module
        metadata=$(git -C module rev-parse --absolute-git-dir)
        printf 'gitdir: %s' "${metadata#?:}" > gitfile
        ;;
esac
