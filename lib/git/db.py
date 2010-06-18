"""Module with our own gitdb implementation - it uses the git command""" 
from gitdb.base import (
								OInfo,
								OStream
							)

from gitdb.db import LooseObjectDB

__all__ = ('GitCmdObjectDB', )

#class GitCmdObjectDB(CompoundDB, ObjectDBW):
class GitCmdObjectDB(LooseObjectDB):
	"""A database representing the default git object store, which includes loose 
	objects, pack files and an alternates file
	
	It will create objects only in the loose object database.
	:note: for now, we use the git command to do all the lookup, just until he 
		have packs and the other implementations
	"""
	def __init__(self, root_path, git):
		"""Initialize this instance with the root and a git command"""
		super(GitCmdObjectDB, self).__init__(root_path)
		self._git = git
		
	def info(self, sha):
		t = self._git.get_object_header(sha)
		return OInfo(*t)
		
	def stream(self, sha):
		"""For now, all lookup is done by git itself"""
		t = self._git.stream_object_data(sha)
		return OStream(*t)
	
