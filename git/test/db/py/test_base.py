# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import *
from git.test.db.base import RepoBase
from git.db.py.complex import *

from git.db.complex import PureCmdGitDB

class TestPyDBBase(RepoBase):
	
	RepoCls = PureCmdGitDB
	
	def test_instantiation(self):
		db = PureGitDB(rorepo_dir())
		cdb = PureCompatibilityGitDB(rorepo_dir())
		
