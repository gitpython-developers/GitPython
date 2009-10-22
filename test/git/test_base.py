# test_base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import git.objects.base as base
import git.refs as refs
import os

from test.testlib import *
from git import *
from itertools import chain
from git.objects.utils import get_object_type_by_name
import tempfile

class TestBase(TestBase):
	
	type_tuples = (  ("blob", "8741fc1d09d61f02ffd8cded15ff603eff1ec070"), 
					 ("tree", "3a6a5e3eeed3723c09f1ef0399f81ed6b8d82e79"),
					 ("commit", "4251bd59fb8e11e40c40548cba38180a9536118c"),
					 ("tag", "e56a60e8e9cd333cfba0140a77cd12b0d9398f10") ) 
	
	def test_base_object(self):	
		# test interface of base object classes
		types = (Blob, Tree, Commit, TagObject)
		assert len(types) == len(self.type_tuples)
		
		s = set()
		num_objs = 0
		num_index_objs = 0
		for obj_type, (typename, hexsha) in zip(types, self.type_tuples):
			item = obj_type(self.rorepo,hexsha)
			num_objs += 1
			assert item.id == hexsha
			assert item.type == typename
			assert item.size
			assert item.data
			assert item == item
			assert not item != item
			assert str(item) == item.id
			assert repr(item)
			s.add(item)
			
			if isinstance(item, base.IndexObject):
				num_index_objs += 1
				if hasattr(item,'path'):						# never runs here
					assert not item.path.startswith("/")		# must be relative
					assert isinstance(item.mode, int)
			# END index object check
			
			# read from stream
			data_stream = item.data_stream
			data = data_stream.read()
			assert data
			
			tmpfile = os.tmpfile()
			assert item == item.stream_data(tmpfile)
			tmpfile.seek(0)
			assert tmpfile.read() == data
			# END stream to file directly
		# END for each object type to create
		
		# each has a unique sha
		assert len(s) == num_objs
		assert len(s|s) == num_objs
		assert num_index_objs == 2
		
		
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
		# see how it dynmically updates its object
		for head in self.rorepo.heads:
			head.name
			head.path
			prev_object = head.object
			cur_object = head.object
			assert prev_object == cur_object		# represent the same git object
			assert prev_object is not cur_object	# but are different instances
		# END for each head
		
	@with_rw_repo('0.1.6')
	def test_head_reset(self, rw_repo):
		cur_head = rw_repo.head
		new_head_commit = cur_head.commit.parents[0]
		reset_head = Head.reset(rw_repo, new_head_commit, index=True)	# index only
		assert reset_head.commit == new_head_commit
		
		self.failUnlessRaises(ValueError, Head.reset, rw_repo, new_head_commit, index=False, working_tree=True)
		new_head_commit = new_head_commit.parents[0]
		reset_head = Head.reset(rw_repo, new_head_commit, index=True, working_tree=True)	# index + wt
		assert reset_head.commit == new_head_commit
		
		# paths
		Head.reset(rw_repo, new_head_commit, paths = "lib")
		
		
	def test_get_object_type_by_name(self):
		for tname in base.Object.TYPES:
			assert base.Object in get_object_type_by_name(tname).mro()
		# END for each known type 
		
		assert_raises( ValueError, get_object_type_by_name, "doesntexist" )

	def test_object_resolution(self):
		# objects must be resolved to shas so they compare equal
		assert self.rorepo.head.object == self.rorepo.active_branch.object
		
	@with_bare_rw_repo
	def test_with_bare_rw_repo(self, bare_rw_repo):
		assert bare_rw_repo.config_reader("repository").getboolean("core", "bare")
		assert os.path.isfile(os.path.join(bare_rw_repo.path,'HEAD'))
		
	@with_rw_repo('0.1.6')
	def test_with_rw_repo(self, rw_repo):
		assert not rw_repo.config_reader("repository").getboolean("core", "bare")
		assert os.path.isdir(os.path.join(rw_repo.git.git_dir,'lib'))
		
	@with_rw_and_rw_remote_repo('0.1.6')
	def test_with_rw_remote_and_rw_repo(self, rw_repo, rw_remote_repo):
		assert not rw_repo.config_reader("repository").getboolean("core", "bare")
		assert rw_remote_repo.config_reader("repository").getboolean("core", "bare")
		assert os.path.isdir(os.path.join(rw_repo.git.git_dir,'lib'))
