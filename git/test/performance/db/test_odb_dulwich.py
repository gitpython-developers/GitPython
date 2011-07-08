try:
	from git.db.dulwich.complex import DulwichCompatibilityGitDB
except ImportError:
	from git.db.complex import PureCompatibilityGitDB as DulwichCompatibilityGitDB
#END handle dulwich compatibility

from git.test.db.dulwich.lib import DulwichRequiredMetaMixin
from odb_impl import TestObjDBPerformanceBase

class TestDulwichDB(TestObjDBPerformanceBase):
	__metaclass__ = DulwichRequiredMetaMixin
	RepoCls = DulwichCompatibilityGitDB
	
