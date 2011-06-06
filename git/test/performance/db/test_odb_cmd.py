from git.db.complex import CmdCompatibilityGitDB
from odb_impl import TestObjDBPerformanceBase

class TestCmdDB(TestObjDBPerformanceBase):
	RepoCls = CmdCompatibilityGitDB
	
