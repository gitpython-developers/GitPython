# test_tag.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from mock import *
from test.testlib import *
from git import *
from git.tag import TagObject
import time

class TestTag(object):
	def setup(self):
		self.repo = Repo(GIT_REPO)

	def test_tag_base(self):
		tag_object_refs = list()
		for tag in self.repo.tags:
			assert "refs/tags" in tag.path
			assert "/" not in tag.name
			assert isinstance( tag.commit, Commit )
			if tag.tag is not None:
				tag_object_refs.append( tag )
				tagobj = tag.tag
				assert isinstance( tagobj, TagObject ) 
				assert tagobj.tag == tag.name
				assert isinstance( tagobj.tagger, Actor )
				assert isinstance( tagobj.tagged_date, time.struct_time )
				assert tagobj.message
			# END if we have a tag object
		# END for tag in repo-tags
		assert tag_object_refs
		

