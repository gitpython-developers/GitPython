# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from lib import *
from git.test.lib import TestBase, with_rw_repo
from git.test.db.base import RepoBase



try:
    import dulwich
except ImportError:
    # om this case, all other dulwich tests will be skipped
    # Need to properly initialize the class though, otherwise it would fail
    from git.db.complex import PureCompatibilityGitDB as DulwichDB
else:
    # now we know dulwich is available, to do futher imports
    from git.db.dulwich.complex import DulwichCompatibilityGitDB as DulwichDB
    
#END handle imports

class TestDulwichDBBase(RepoBase):
    __metaclass__ = DulwichRequiredMetaMixin
    RepoCls = DulwichDB
    
    @needs_dulwich_or_skip
    @with_rw_repo('HEAD', bare=False)
    def test_basics(self, rw_repo):
        db = DulwichDB(rw_repo.working_tree_dir)
        
        
