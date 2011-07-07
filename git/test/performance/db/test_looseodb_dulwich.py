from git.db.dulwich.complex import DulwichGitODB
from looseodb_impl import TestLooseDBWPerformanceBase

class TestPureLooseDB(TestLooseDBWPerformanceBase):
	LooseODBCls = DulwichGitODB
	
