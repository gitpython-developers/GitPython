# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import rorepo_dir
from git.test.db.base import RepoBase

# import test
from git.db.py.base import *
from git.db.py.loose import *
from git.db.py.mem import *
from git.db.py.pack import *
from git.db.py.ref import *
from git.db.py.resolve import *
from git.db.py.submodule import *
from git.db.py.transport import *
from git.db.py.complex import *

from git.db.complex import PureCompatibilityGitDB

class TestPyDBBase(RepoBase):
	
	RepoCls = PureCompatibilityGitDB
	
	def test_basics(self):
		pass
		
