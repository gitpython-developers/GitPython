# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from lib import *
from git.test.db.base import RepoBase
from git.db.complex import PureCompatibilityGitDB

try:
	import dulwich
except ImportError:
	# om this case, all other dulwich tests will be skipped
	pass

class TestPyDBBase(RepoBase):
	__metaclass__ = DulwichRequiredMetaMixin
	RepoCls = PureCompatibilityGitDB
	
	@needs_dulwich_or_skip
	def test_basics(self):
		import dulwich
		pass
		
