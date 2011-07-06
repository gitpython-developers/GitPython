# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.db.base import RepoBase
from git.db.complex import PureCompatibilityGitDB

try:
	import git.db.dulwich		# import test

	class TestPyDBBase(RepoBase):
		
		RepoCls = PureCompatibilityGitDB
		
	#	def test_basics(self):
	#		pass
			
except ImportError:
	del(RepoBase)
	import warnings
	warnings.warn("Skipped all dulwich tests as they are not in the path")
#END handle import
