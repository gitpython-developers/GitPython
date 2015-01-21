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
        assert repo.bare == False
        # ![1-test_init_repo_object]

        # [2-test_init_repo_object]
        bare_empty_repo = Repo.init(join(rw_dir, 'bare-repo'), bare=True)
        assert bare_empty_repo.bare == True
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
        assert repo.clone(join(rw_dir, 'to/this/path')).__class__ is Repo
        assert Repo.init(join(rw_dir, 'path/for/new/repo')).__class__ is Repo
        # ![5-test_init_repo_object]
        
        # [6-test_init_repo_object]
        repo.archive(open(join(rw_dir, 'repo.tar'), 'w'))
        # ![6-test_init_repo_object]

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
