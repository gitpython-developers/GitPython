# test_index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestTree(TestCase):
	
	@classmethod
	def setUpAll(cls):
		cls.repo = Repo(GIT_REPO)
		
	def test_base(self):
		self.fail("TODO")
