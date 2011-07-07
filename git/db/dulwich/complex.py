
__all__ = ['DulwichGitODB', 'DulwichGitDB', 'DulwichCompatibilityGitDB']

from git.db.py.complex import PureGitODB
from git.db.py.base import (
						PureRepositoryPathsMixin,
						PureConfigurationMixin,
						PureIndexDB,
					)
from git.db.py.resolve import PureReferencesMixin
from git.db.py.transport import PureTransportDB
from git.db.py.submodule import PureSubmoduleDB

from git.db.cmd.complex import CmdHighLevelRepository, GitCommandMixin
from git.db.compat import RepoCompatibilityInterfaceNoBare

#from git.db.interface import ObjectDBW, ObjectDBR
from dulwich.repo import Repo as DulwichRepo

import os


class DulwichGitODB(PureGitODB):
	"""A full fledged database to read and write object files from all kinds of sources."""
	
	def __init__(self, objects_root):
		"""Initalize this instance"""
		PureGitODB.__init__(self, objects_root)
		self._dw_repo = DulwichRepo(self.working_dir)
		
	def __getattr__(self, attr):
		try:
			# supply LazyMixin with this call first
			return super(DulwichGitODB, self).__getattr__(attr)
		except AttributeError:
			# now assume its on the dulwich repository ... for now
			return getattr(self._dw_repo, attr)
		#END handle attr
		
		
class DulwichGitDB(		PureRepositoryPathsMixin, PureConfigurationMixin, 
						PureReferencesMixin, PureSubmoduleDB, 
						PureIndexDB, 
						PureTransportDB, # not fully implemented
						GitCommandMixin,
						CmdHighLevelRepository,
						DulwichGitODB):	# must come last, as it doesn't pass on __init__ with super


	def __init__(self, root_path):
		"""Initialize ourselves on the .git directory, or the .git/objects directory."""
		PureRepositoryPathsMixin._initialize(self, root_path)
		super(DulwichGitDB, self).__init__(self.objects_dir)
	

class DulwichCompatibilityGitDB(RepoCompatibilityInterfaceNoBare, DulwichGitDB):
	"""Basic dulwich compatibility database"""
	pass

