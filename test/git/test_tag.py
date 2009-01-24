# test_tag.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from mock import *
from test.testlib import *
from git import *

class TestTag(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)

    @patch_object(Git, '_call_process')
    def test_list_from_string(self, git):
        git.return_value = fixture('for_each_ref_tags')
        
        tags = self.repo.tags
        
        assert_equal(1, len(tags))
        assert_equal('v0.7.1', tags[0].name)
        assert_equal('634396b2f541a9f2d58b00be1a07f0c358b999b3', tags[0].commit.id)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/tags'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))

    @patch_object(Git, '_call_process')
    def test_repr(self, git):
        git.return_value = fixture('for_each_ref')
        
        tag = self.repo.tags[0]
        assert_equal('<git.Tag "%s">' % tag.name, repr(tag))
        
        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/tags'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))
