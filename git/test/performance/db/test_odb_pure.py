from git.db.complex import PureCompatibilityGitDB
from odb_impl import TestObjDBPerformanceBase

class TestPureDB(TestObjDBPerformanceBase):
	RepoCls = PureCompatibilityGitDB
	
