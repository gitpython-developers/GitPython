
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
from dulwich.objects import ShaFile

from git.base import OInfo, OStream
from git.fun import type_id_to_type_map, type_to_type_id_map 

from cStringIO import StringIO 
import os


class DulwichGitODB(PureGitODB):
	"""A full fledged database to read and write object files from all kinds of sources."""
	
	def __init__(self, objects_root):
		"""Initalize this instance"""
		PureGitODB.__init__(self, objects_root)
		if hasattr(self, 'working_dir'):
			wd = self.working_dir
		else:
			wd = os.path.dirname(os.path.dirname(objects_root))
		#END try to figure out good entry for dulwich, which doesn't do an extensive search
		self._dw_repo = DulwichRepo(wd)
		
	def __getattr__(self, attr):
		try:
			# supply LazyMixin with this call first
			return super(DulwichGitODB, self).__getattr__(attr)
		except AttributeError:
			# now assume its on the dulwich repository ... for now
			return getattr(self._dw_repo, attr)
		#END handle attr
		
	#{ Object DBR
	
	def info(self, binsha):
		type_id, uncomp_data = self._dw_repo.object_store.get_raw(binsha) 
		return OInfo(binsha, type_id_to_type_map[type_id], len(uncomp_data))
	
	def stream(self, binsha):
		type_id, uncomp_data = self._dw_repo.object_store.get_raw(binsha)
		return OStream(binsha, type_id_to_type_map[type_id], len(uncomp_data), StringIO(uncomp_data))
	
	#}END object dbr
	
	#{ Object DBW
	
	def store(self, istream):
		obj = ShaFile.from_raw_string(type_to_type_id_map[istream.type], istream.read())
		self._dw_repo.object_store.add_object(obj)
		istream.binsha = obj.sha().digest()
		return istream
		
	#}END object dbw
		
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

