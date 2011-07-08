
__all__ = ['Pygit2GitODB', 'Pygit2GitDB', 'Pygit2CompatibilityGitDB']

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
from git.db.compat import RepoCompatibilityInterface

from pygit2 import Repository as Pygit2Repo

from git.base import OInfo, OStream
from git.fun import type_id_to_type_map, type_to_type_id_map
from git.util import hex_to_bin

from cStringIO import StringIO 
import os


class Pygit2GitODB(PureGitODB):
	"""A full fledged database to read and write object files from all kinds of sources."""
	
	def __init__(self, objects_root):
		"""Initalize this instance"""
		PureGitODB.__init__(self, objects_root)
		if hasattr(self, 'git_dir'):
			wd = self.git_dir
		else:
			wd = os.path.dirname(objects_root)
		#END try to figure out good entry for pygit2 - it needs the .gitdir
		print objects_root
		print wd
		self._py2_repo = Pygit2Repo(wd)
		
	def __getattr__(self, attr):
		try:
			# supply LazyMixin with this call first
			return super(Pygit2GitODB, self).__getattr__(attr)
		except AttributeError:
			# now assume its on the pygit2 repository ... for now
			return getattr(self._py2_repo, attr)
		#END handle attr
		
	#{ Object DBR
	
	def info(self, binsha):
		type_id, uncomp_data = self._py2_repo.read(binsha) 
		return OInfo(binsha, type_id_to_type_map[type_id], len(uncomp_data))
	 
	def stream(self, binsha):
		type_id, uncomp_data = self._py2_repo.read(binsha)
		return OStream(binsha, type_id_to_type_map[type_id], len(uncomp_data), StringIO(uncomp_data))
	 
	# #}END object dbr
	# 
	# #{ Object DBW
	def store(self, istream):
		# TODO: remove this check once the required functionality was merged in pygit2
		if hasattr(self._py2_repo, 'write'):
			istream.binsha = hex_to_bin(self._py2_repo.write(type_to_type_id_map[istream.type], istream.read()))
			return istream
		else:
			return super(Pygit2GitODB, self).store(istream)
		#END handle write support
		
	#}END object dbw
		
class Pygit2GitDB(		PureRepositoryPathsMixin, PureConfigurationMixin, 
						PureReferencesMixin, PureSubmoduleDB, 
						PureIndexDB, 
						PureTransportDB, # not fully implemented
						GitCommandMixin,
						CmdHighLevelRepository,
						Pygit2GitODB):	# must come last, as it doesn't pass on __init__ with super


	def __init__(self, root_path):
		"""Initialize ourselves on the .git directory, or the .git/objects directory."""
		PureRepositoryPathsMixin._initialize(self, root_path)
		super(Pygit2GitDB, self).__init__(self.objects_dir)
	

class Pygit2CompatibilityGitDB(RepoCompatibilityInterface, Pygit2GitDB):
	"""Basic pygit2 compatibility database"""
	pass

