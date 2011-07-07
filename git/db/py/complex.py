# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of PurePartialGitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.db.interface import HighLevelRepository
from base import (
						PureCompoundDB, 
						PureObjectDBW, 
						PureRootPathDB, 
						PureRepositoryPathsMixin,
						PureConfigurationMixin,
						PureAlternatesFileMixin,
						PureIndexDB,
					)
from transport import PureTransportDB
from resolve import PureReferencesMixin

from loose import PureLooseObjectODB
from pack import PurePackedODB
from ref import PureReferenceDB
from submodule import PureSubmoduleDB

from git.db.compat import RepoCompatibilityInterface

from git.exc import InvalidDBRoot
import os

__all__ = ('PureGitODB', 'PurePartialGitDB', 'PureCompatibilityGitDB')


class PureGitODB(PureRootPathDB, PureObjectDBW, PureCompoundDB, PureAlternatesFileMixin):
	"""A git-style object-only database, which contains all objects in the 'objects'
	subdirectory.
	:note: The type needs to be initialized on the ./objects directory to function, 
		as it deals solely with object lookup. Use a PurePartialGitDB type if you need
		reference and push support."""
	# Configuration
	PackDBCls = PurePackedODB
	LooseDBCls = PureLooseObjectODB
	PureReferenceDBCls = PureReferenceDB
	
	# Directories
	packs_dir = 'pack'
	loose_dir = ''
	
	
	def __init__(self, root_path):
		"""Initialize ourselves on a git ./objects directory"""
		super(PureGitODB, self).__init__(root_path)
		
	def _set_cache_(self, attr):
		if attr == '_dbs' or attr == '_loose_db':
			self._dbs = list()
			loose_db = None
			for subpath, dbcls in ((self.packs_dir, self.PackDBCls), 
									(self.loose_dir, self.LooseDBCls),
									(self.alternates_filepath, self.PureReferenceDBCls)):
				path = self.db_path(subpath)
				if os.path.exists(path):
					self._dbs.append(dbcls(path))
					if dbcls is self.LooseDBCls:
						loose_db = self._dbs[-1]
					# END remember loose db
				# END check path exists
			# END for each db type
			
			# should have at least one subdb
			if not self._dbs:
				raise InvalidDBRoot(self.root_path())
			# END handle error
			
			# we the first one should have the store method
			assert loose_db is not None and hasattr(loose_db, 'store'), "One database needs store functionality"
			
			# finally set the value
			self._loose_db = loose_db
		else:
			super(PureGitODB, self)._set_cache_(attr)
		# END handle attrs
		
	#{ PureObjectDBW interface
		
	def store(self, istream):
		return self._loose_db.store(istream)
		
	def ostream(self):
		return self._loose_db.ostream()
	
	def set_ostream(self, ostream):
		return self._loose_db.set_ostream(ostream)
		
	#} END objectdbw interface
	
	
	
class PurePartialGitDB(PureGitODB, 
				PureRepositoryPathsMixin, PureConfigurationMixin, 
				PureReferencesMixin, PureSubmoduleDB, 
				PureIndexDB, 
				PureTransportDB # not fully implemented
				# HighLevelRepository  Currently not implemented !
				):
	"""Git like database with support for object lookup as well as reference resolution.
	Our rootpath is set to the actual .git directory (bare on unbare).
	
	The root_path will be the git objects directory. Use git_path() to obtain the actual top-level 
	git directory."""
	#directories
	
	def __init__(self, root_path):
		"""Initialize ourselves on the .git directory, or the .git/objects directory."""
		PureRepositoryPathsMixin._initialize(self, root_path)
		super(PurePartialGitDB, self).__init__(self.objects_dir)
	
	
class PureCompatibilityGitDB(PurePartialGitDB, RepoCompatibilityInterface):
	"""Pure git database with a compatability layer required by 0.3x code"""
	
