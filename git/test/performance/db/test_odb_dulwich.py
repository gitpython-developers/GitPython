from git.db.dulwich.complex import DulwichCompatibilityGitDB
from odb_impl import TestObjDBPerformanceBase

class TestPureDB(TestObjDBPerformanceBase):
	RepoCls = DulwichCompatibilityGitDB
	
