#-*-coding:utf-8-*-
# test_git.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os

import git
from git.test.lib import TestBase
from gitdb.test.lib import with_rw_directory
from git.repo.fun import touch


class TestGit(TestBase):

    @with_rw_directory
    def test_add_file_and_commit(self, rw_dir):
        repo_dir = os.path.join(rw_dir, 'my-new-repo')
        file_name = os.path.join(repo_dir, 'new-file')

        r = git.Repo.init(repo_dir)
        # This function just creates an empty file ...
        touch(file_name)
        r.index.add([file_name])
        r.index.commit("initial commit")
