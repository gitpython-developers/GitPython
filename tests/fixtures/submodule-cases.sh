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
    remove-dirty-index|remove-dirty-worktree|remove-dirty-untracked)
        add_module module module
        path="file"
        if test "$scenario" = remove-dirty-untracked; then path=untracked; fi
        printf 'keep this data\n' > "parent/module/$path"
        if test "$scenario" = remove-dirty-index; then git -C parent/module add file; fi
        ;;
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
    branch-dot|branch-dot-alias|root-url-branch-dot|root-reuse-inherited-branch)
        git init -q -b master source
        git -C source commit --allow-empty -qm initial
        git -C source branch dev
        printf 'master\n' > source/file
        git -C source add file
        git -C source commit -qm 'Advance master'
        git -C source checkout -q dev
        printf 'dev\n' > source/file
        git -C source add file
        git -C source commit -qm 'Advance dev'
        git -C source checkout -q master
        source="$root/source"
        add_module module module
        if test "$scenario" = root-reuse-inherited-branch; then
            git -C parent config -f .gitmodules submodule.module.branch master
            git -C parent commit -qam 'Track master'
            git -C parent checkout -qb dev
            git -C parent/module branch dev origin/dev
            git -C parent tag before-branch-change
            git -C parent update-index --cacheinfo "160000,$(git -C source rev-parse dev),module"
        fi
        git -C parent config -f .gitmodules submodule.module.branch .
        git -C parent add .gitmodules
        git -C parent commit -qm 'Track the superproject branch'
        if test "$scenario" = root-reuse-inherited-branch; then exit 0; fi
        git -C parent branch dev
        git clone -q -b dev parent clone
        if test "$scenario" = branch-dot-alias; then
            git -C clone branch master refs/remotes/origin/master
            git -C clone symbolic-ref refs/heads/dev refs/heads/master
        fi
        if test "$scenario" = root-url-branch-dot; then
            git -C clone submodule update --init
            git -C clone tag before-url-change
            git clone -q -b dev source moved
            git -C moved commit --allow-empty -qm 'Advance dev on the replacement remote'
            git -C clone config -f .gitmodules submodule.module.url "$root/moved"
            git -C clone commit -qam 'Change submodule URL'
            git -C clone checkout -q --detach HEAD
        fi
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
