# test_refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from mock import *
from test.testlib import *
from git import *
import git.refs as refs
from git.objects.tag import TagObject
from itertools import chain

class TestRefs(TestBase):

	def test_tag_base(self):
		tag_object_refs = list()
		for tag in self.rorepo.tags:
			assert "refs/tags" in tag.path
			assert tag.name
			assert isinstance( tag.commit, Commit )
			if tag.tag is not None:
				tag_object_refs.append( tag )
				tagobj = tag.tag
				assert isinstance( tagobj, TagObject ) 
				assert tagobj.tag == tag.name
				assert isinstance( tagobj.tagger, Actor )
				assert isinstance( tagobj.tagged_date, int )
				assert tagobj.message
			# END if we have a tag object
		# END for tag in repo-tags
		assert tag_object_refs
		assert isinstance(self.rorepo.tags['0.1.5'], TagReference)
		
	@patch_object(Git, '_call_process')
	def test_ref_with_path_component(self, git):
		git.return_value = fixture('for_each_ref_with_path_component')
		head = self.rorepo.heads[0]

		assert_equal('refactoring/feature1', head.name)
		assert_true(git.called)
		

	def test_tags(self):
		# tag refs can point to tag objects or to commits
		s = set()
		ref_count = 0
		for ref in chain(self.rorepo.tags, self.rorepo.heads):
			ref_count += 1
			assert isinstance(ref, refs.Reference)
			assert str(ref) == ref.name
			assert repr(ref)
			assert ref == ref
			assert not ref != ref
			s.add(ref)
		# END for each ref
		assert len(s) == ref_count
		assert len(s|s) == ref_count
		
	def test_heads(self):
		for head in self.rorepo.heads:
			assert head.name
			assert head.path
			assert "refs/heads" in head.path
			prev_object = head.object
			cur_object = head.object
			assert prev_object == cur_object		# represent the same git object
			assert prev_object is not cur_object	# but are different instances
		# END for each head
		
	@with_rw_repo('0.1.6')
	def test_head_reset(self, rw_repo):
		cur_head = rw_repo.head
		new_head_commit = cur_head.ref.commit.parents[0]
		reset_head = Head.reset(rw_repo, new_head_commit, index=True)	# index only
		assert reset_head.commit == new_head_commit
		
		self.failUnlessRaises(ValueError, Head.reset, rw_repo, new_head_commit, index=False, working_tree=True)
		new_head_commit = new_head_commit.parents[0]
		reset_head = Head.reset(rw_repo, new_head_commit, index=True, working_tree=True)	# index + wt
		assert reset_head.commit == new_head_commit
		
		# paths
		Head.reset(rw_repo, new_head_commit, paths = "lib")
