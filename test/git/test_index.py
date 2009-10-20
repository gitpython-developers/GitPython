# test_index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *
import inspect

class TestTree(TestCase):
	
	@classmethod
	def setUpAll(cls):
		cls.repo = Repo(GIT_REPO)
		
	def test_base(self):
		# read from file
		index = Index.from_file(fixture_path("index"))
		assert index.entries
		assert index.version > 0
		
		# test entry
		last_val = None
		entry = index.entries.itervalues().next()
		for name, method in inspect.getmembers(entry,inspect.ismethod):
			val = method(entry)
			assert val != last_val
			last_val = val
		# END for each method
		
		# write
		self.fail("writing, object type and stage")
