# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from lib import *
from git.test.lib import TestBase, with_rw_repo
from git.test.db.base import RepoBase



try:
	import pygit2
except ImportError:
	# om this case, all other pygit2 tests will be skipped
	# Need to properly initialize the class though, otherwise it would fail
	from git.db.complex import PureCompatibilityGitDB as Pygit2DB
else:
	# now we know pygit2 is available, to do futher imports
	from git.db.pygit2.complex import Pygit2CompatibilityGitDB as Pygit2DB
	
#END handle imports

class TestPyGit2DBBase(RepoBase):
	__metaclass__ = Pygit2RequiredMetaMixin
	RepoCls = Pygit2DB
	
	@needs_pygit2_or_skip
	@with_rw_repo('HEAD', bare=False)
	def test_basics(self, rw_repo):
		db = Pygit2DB(rw_repo.working_tree_dir)
		
		
