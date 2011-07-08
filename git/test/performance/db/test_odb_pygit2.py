try:
	from git.db.pygit2.complex import Pygit2CompatibilityGitDB
except ImportError:
	from git.db.complex import PureCompatibilityGitDB as Pygit2CompatibilityGitDB
#END handle pygit2 compatibility

from git.test.db.pygit2.lib import Pygit2RequiredMetaMixin
from odb_impl import TestObjDBPerformanceBase

class TestPygit2DB(TestObjDBPerformanceBase):
	__metaclass__ = Pygit2RequiredMetaMixin
	RepoCls = Pygit2CompatibilityGitDB
	
