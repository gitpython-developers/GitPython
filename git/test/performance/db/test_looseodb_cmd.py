from git.db.complex import CmdCompatibilityGitDB
from looseodb_impl import TestLooseDBWPerformanceBase

import sys

class TestCmdLooseDB(TestLooseDBWPerformanceBase):
	LooseODBCls = CmdCompatibilityGitDB
	
	def test_info(self):
		sys.stderr.write("This test does not check the write performance of the git command as it is implemented in pure python")   
	
