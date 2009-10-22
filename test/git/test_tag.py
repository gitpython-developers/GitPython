# test_tag.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from mock import *
from test.testlib import *
from git import *
from git.objects.tag import TagObject

class TestTag(TestBase):

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
		

