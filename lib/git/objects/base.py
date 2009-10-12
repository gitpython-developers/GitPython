# base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os
from git.utils import LazyMixin
	
		
class Object(LazyMixin):
	"""
	Implements an Object which may be Blobs, Trees, Commits and Tags
	"""
	TYPES = ("blob", "tree", "commit", "tag")
	__slots__ = ("repo", "id", "size", "data" )
	type = None			# to be set by subclass
	
	def __init__(self, repo, id):
		"""
		Initialize an object by identifying it by its id. All keyword arguments
		will be set on demand if None.
		
		``repo``
			repository this object is located in
			
		``id``
			SHA1 or ref suitable for git-rev-parse
		"""
		super(Object,self).__init__()
		self.repo = repo
		self.id = id
		
	def _set_self_from_args_(self, args_dict):
		"""
		Initialize attributes on self from the given dict that was retrieved
		from locals() in the calling method.
		
		Will only set an attribute on self if the corresponding value in args_dict
		is not None
		"""
		for attr, val in args_dict.items():
			if attr != "self" and val is not None:
				setattr( self, attr, val )
		# END set all non-None attributes
	
	def _set_cache_(self, attr):
		"""
		Retrieve object information
		"""
		if attr  == "size":
			self.size = int(self.repo.git.cat_file(self.id, s=True).rstrip())
		elif attr == "data":
			self.data = self.repo.git.cat_file(self.id, p=True, with_raw_output=True)
		
	def __eq__(self, other):
		"""
		Returns
			True if the objects have the same SHA1
		"""
		return self.id == other.id
		
	def __ne__(self, other):
		"""
		Returns
			True if the objects do not have the same SHA1
		"""
		return self.id != other.id
		
	def __hash__(self):
		"""
		Returns
			Hash of our id allowing objects to be used in dicts and sets
		"""
		return hash(self.id)
		
	def __str__(self):
		"""
		Returns
			string of our SHA1 as understood by all git commands
		"""
		return self.id
		
	def __repr__(self):
		"""
		Returns
			string with pythonic representation of our object
		"""
		return '<git.%s "%s">' % (self.__class__.__name__, self.id)


class IndexObject(Object):
	"""
	Base for all objects that can be part of the index file , namely Tree, Blob and
	SubModule objects
	"""
	__slots__ = ("path", "mode") 
	
	def __init__(self, repo, id, mode=None, path=None):
		"""
		Initialize a newly instanced IndexObject
		``repo``
			is the Repo we are located in

		``id`` : string
			is the git object id as hex sha

		``mode`` : int
			is the file mode as int, use the stat module to evaluate the infomration

		``path`` : str
			is the path to the file in the file system, relative to the git repository root, i.e.
			file.ext or folder/other.ext
				
		NOTE
			Path may not be set of the index object has been created directly as it cannot
			be retrieved without knowing the parent tree.
		"""
		super(IndexObject, self).__init__(repo, id)
		self._set_self_from_args_(locals())
		if isinstance(mode, basestring):
			self.mode = self._mode_str_to_int(mode)
	
	@classmethod
	def _mode_str_to_int( cls, modestr ):
		"""
		``modestr``
			string like 755 or 644 or 100644 - only the last 3 chars will be used
			
		Returns
			String identifying a mode compatible to the mode methods ids of the 
			stat module regarding the rwx permissions for user, group and other
		"""
		mode = 0
		for iteration,char in enumerate(reversed(modestr[-3:])):
			mode += int(char) << iteration*3
		# END for each char
		return mode
	  
		
