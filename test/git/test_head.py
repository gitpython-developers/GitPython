# test_head.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestHead(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)

    @patch_object(Git, '_call_process')
    def test_repr(self, git):
        git.return_value = fixture('for_each_ref')
        
        head = self.repo.heads[0]
        
        assert_equal('<git.Head "%s">' % head.name, repr(head))
        
        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/heads'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))

    @patch_object(Git, '_call_process')
    def test_ref_with_path_component(self, git):
        git.return_value = fixture('for_each_ref_with_path_component')
        head = self.repo.heads[0]

        assert_equal('refactoring/feature1', head.name)
        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/heads'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))
