try:
	from git.db.dulwich.complex import DulwichGitODB
except ImportError:
	from git.db.py.complex import PureGitODB as DulwichGitODB
#END handle import 

from git.test.db.dulwich.lib import DulwichRequiredMetaMixin
from looseodb_impl import TestLooseDBWPerformanceBase

class TestPureLooseDB(TestLooseDBWPerformanceBase):
	__metaclass__ = DulwichRequiredMetaMixin
	LooseODBCls = DulwichGitODB
	
