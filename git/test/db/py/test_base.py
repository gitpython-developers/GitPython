# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import rorepo_dir
from git.test.db.base import RepoBase

from git.db.complex import PureCompatibilityGitDB

class TestPyDBBase(RepoBase):
	
	RepoCls = PureCompatibilityGitDB
	
	def test_basics(self):
		pass
		
