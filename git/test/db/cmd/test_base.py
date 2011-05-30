# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import rorepo_dir
from git.test.db.base import RepoBase

# immport test
from git.db.cmd.base import *
from git.db.cmd.complex import *

from git.db.complex import CmdCompatibilityGitDB

class TestBase(RepoBase):
	RepoCls = CmdCompatibilityGitDB

	def test_basics(self):
		pass
