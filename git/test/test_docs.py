#-*-coding:utf-8-*-
# test_git.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os

from git.test.lib import TestBase
from gitdb.test.lib import with_rw_directory


class Tutorials(TestBase):

    @with_rw_directory
    def test_init_repo_object(self, rw_dir):
        from git import Repo
        join = os.path.join

        # rorepo is a a Repo instance pointing to the git-python repository.
        # For all you know, the first argument to Repo is a path to the repository
        # you want to work with
        repo = Repo(self.rorepo.working_tree_dir)
        assert not repo.bare
        # ![1-test_init_repo_object]

        # [2-test_init_repo_object]
        bare_repo = Repo.init(join(rw_dir, 'bare-repo'), bare=True)
        assert bare_repo.bare
        # ![2-test_init_repo_object]

        # [3-test_init_repo_object]
        repo.config_reader()             # get a config reader for read-only access
        cw = repo.config_writer()        # get a config writer to change configuration
        cw.release()                     # call release() to be sure changes are written and locks are released
        # ![3-test_init_repo_object]

        # [4-test_init_repo_object]
        repo.is_dirty()
        # False
        repo.untracked_files
        # ['my_untracked_file']
        # ![4-test_init_repo_object]

        # [5-test_init_repo_object]
        cloned_repo = repo.clone(join(rw_dir, 'to/this/path'))
        assert cloned_repo.__class__ is Repo     # clone an existing repository
        assert Repo.init(join(rw_dir, 'path/for/new/repo')).__class__ is Repo
        # ![5-test_init_repo_object]

        # [6-test_init_repo_object]
        repo.archive(open(join(rw_dir, 'repo.tar'), 'wb'))
        # ![6-test_init_repo_object]

        # repository paths
        # [7-test_init_repo_object]
        assert os.path.isdir(cloned_repo.working_tree_dir)                    # directory with your work files
        assert cloned_repo.git_dir.startswith(cloned_repo.working_tree_dir)   # directory containing the git repository
        assert bare_repo.working_tree_dir is None                             # bare repositories have no working tree
        # ![7-test_init_repo_object]

        # heads, tags and references
        # heads are branches in git-speak
        # [8-test_init_repo_object]
        assert repo.head.ref == repo.heads.master                   # head is a symbolic reference pointing to master
        assert repo.tags['0.3.5'] == repo.tag('refs/tags/0.3.5')    # you can access tags in various ways too
        assert repo.refs.master == repo.heads['master']             # .refs provides access to all refs, i.e. heads ...
        assert repo.refs['origin/master'] == repo.remotes.origin.refs.master  # ... remotes ...
        assert repo.refs['0.3.5'] == repo.tags['0.3.5']             # ... and tags
        # ![8-test_init_repo_object]

        # create a new head/branch
        # [9-test_init_repo_object]
        new_branch = cloned_repo.create_head('feature')               # create a new branch ...
        assert cloned_repo.active_branch != new_branch                # which wasn't checked out yet ...
        assert new_branch.commit == cloned_repo.active_branch.commit  # and which points to the checked-out commit
        # It's easy to let a branch point to the previous commit, without affecting anything else
        # Each reference provides access to the git object it points to, usually commits
        assert new_branch.set_commit('HEAD~1').commit == cloned_repo.active_branch.commit.parents[0]
        # ![9-test_init_repo_object]

        # create a new tag reference
        # [10-test_init_repo_object]
        past = cloned_repo.create_tag('past', ref=new_branch,
                                      message="This is a tag-object pointing to %s" % new_branch.name)
        assert past.commit == new_branch.commit        # the tag points to the specified commit
        assert past.tag.message.startswith("This is")  # and its object carries the message provided

        now = cloned_repo.create_tag('now')            # This is a tag-reference. It may not carry meta-data
        assert now.tag is None
        # ![10-test_init_repo_object]

        # Object handling
        # [11-test_init_repo_object]
        assert now.commit.message != past.commit.message
        # You can read objects directly through binary streams, no working tree required
        assert (now.commit.tree / 'VERSION').data_stream.read().decode('ascii').startswith('0')

        # You can traverse trees as well to handle all contained files of a particular commit
        file_count = 0
        tree_count = 0
        tree = past.commit.tree
        for item in tree.traverse():
            file_count += item.type == 'blob'
            tree_count += item.type == 'tree'
        assert file_count and tree_count                        # we have accumulated all directories and files
        assert len(tree.blobs) + len(tree.trees) == len(tree)   # a tree is iterable itself to traverse its children
        # ![11-test_init_repo_object]

        # remotes allow handling push, pull and fetch operations
        # [12-test_init_repo_object]
        from git import RemoteProgress

        class MyProgressPrinter(RemoteProgress):
            def update(self, op_code, cur_count, max_count=None, message=''):
                print(op_code, cur_count, max_count, cur_count / (max_count or 100.0), message or "NO MESSAGE")
        # end

        assert len(cloned_repo.remotes) == 1                    # we have been cloned, so there should be one remote
        assert len(bare_repo.remotes) == 0                      # this one was just initialized
        origin = bare_repo.create_remote('origin', url=cloned_repo.working_tree_dir)
        assert origin.exists()
        for fetch_info in origin.fetch(progress=MyProgressPrinter()):
            print("Updated %s to %s" % (fetch_info.ref, fetch_info.commit))
        # create a local branch at the latest fetched master. We specify the name statically, but you have all
        # information to do it programatically as well.
        bare_master = bare_repo.create_head('master', origin.refs.master)
        bare_repo.head.set_reference(bare_master)
        assert not bare_repo.delete_remote(origin).exists()
        # push and pull behave very similarly
        # ![12-test_init_repo_object]

        # index
        # [13-test_init_repo_object]
        assert new_branch.checkout() == cloned_repo.active_branch     # checking out a branch adjusts the working tree
        assert new_branch.commit == past.commit                       # Now the past is checked out

        new_file_path = os.path.join(cloned_repo.working_tree_dir, 'my-new-file')
        open(new_file_path, 'wb').close()                             # create new file in working tree
        cloned_repo.index.add([new_file_path])                        # add it to the index
        # Commit the changes to deviate masters history
        cloned_repo.index.commit("Added a new file in the past - for later merege")

        # prepare a merge
        master = cloned_repo.heads.master                         # right-hand side is ahead of us, in the future
        merge_base = cloned_repo.merge_base(new_branch, master)   # allwos for a three-way merge
        cloned_repo.index.merge_tree(master, base=merge_base)     # write the merge result into index
        cloned_repo.index.commit("Merged past and now into future ;)",
                                 parent_commits=(new_branch.commit, master.commit))

        # now new_branch is ahead of master, which probably should be checked out and reset softly.
        # note that all these operations didn't touch the working tree, as we managed it ourselves.
        # This definitely requires you to know what you are doing :) !
        assert os.path.basename(new_file_path) in new_branch.commit.tree  # new file is now in tree
        master.commit = new_branch.commit            # let master point to most recent commit
        cloned_repo.head.reference = master          # we adjusted just the reference, not the working tree or index
        # ![13-test_init_repo_object]

        # submodules

        # [14-test_init_repo_object]
        # create a new submodule and check it out on the spot, setup to track master branch of `bare_repo`
        # As our GitPython repository has submodules already that point to github, make sure we don't
        # interact with them
        for sm in cloned_repo.submodules:
            assert not sm.remove().exists()                   # after removal, the sm doesn't exist anymore
        sm = cloned_repo.create_submodule('mysubrepo', 'path/to/subrepo', url=bare_repo.git_dir, branch='master')
        
        # .gitmodules was written and added to the index, which is now being committed
        cloned_repo.index.commit("Added submodule")
        assert sm.exists() and sm.module_exists()             # this submodule is defintely available
        sm.remove(module=True, configuration=False)           # remove the working tree
        assert sm.exists() and not sm.module_exists()         # the submodule itself is still available

        # update all submodules, non-recursively to save time, this method is very powerful, go have a look
        cloned_repo.submodule_update(recursive=False)
        assert sm.module_exists()                             # The submodules working tree was checked out by update
        # ![14-test_init_repo_object]

    @with_rw_directory
    def test_add_file_and_commit(self, rw_dir):
        import git

        repo_dir = os.path.join(rw_dir, 'my-new-repo')
        file_name = os.path.join(repo_dir, 'new-file')

        r = git.Repo.init(repo_dir)
        # This function just creates an empty file ...
        open(file_name, 'wb').close()
        r.index.add([file_name])
        r.index.commit("initial commit")

        # ![test_add_file_and_commit]
