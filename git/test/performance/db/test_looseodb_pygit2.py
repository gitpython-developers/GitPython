try:
	from git.db.pygit2.complex import Pygit2GitODB
except ImportError:
	from git.db.py.complex import PureGitODB as Pygit2GitODB
#END handle import 

from git.test.db.pygit2.lib import Pygit2RequiredMetaMixin
from looseodb_impl import TestLooseDBWPerformanceBase

class TestPureLooseDB(TestLooseDBWPerformanceBase):
	__metaclass__ = Pygit2RequiredMetaMixin
	LooseODBCls = Pygit2GitODB
	
