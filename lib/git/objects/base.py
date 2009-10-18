# base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os
from git.utils import LazyMixin
import utils
	
_assertion_msg_format = "Created object %r whose python type %r disagrees with the acutal git object type %r"

class Object(LazyMixin):
	"""
	Implements an Object which may be Blobs, Trees, Commits and Tags
	
	This Object also serves as a constructor for instances of the correct type::
	
		inst = Object.new(repo,id)
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

	@classmethod
	def new(cls, repo, id):
		"""
		Return
			New Object instance of a type appropriate to the object type behind 
			id. The id of the newly created object will be a hexsha even though 
			the input id may have been a Reference or Rev-Spec
			
		Note
			This cannot be a __new__ method as it would always call __init__
			with the input id which is not necessarily a hexsha.
		"""
		hexsha, typename, size = repo.git.get_object_header(id)
		obj_type = utils.get_object_type_by_name(typename)
		inst = obj_type(repo, hexsha)
		inst.size = size
		return inst
	
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
			hexsha, typename, self.size = self.repo.git.get_object_header(self.id)
			assert typename == self.type, _assertion_msg_format % (self.id, typename, self.type)
		elif attr == "data":
			hexsha, typename, self.size, self.data = self.repo.git.get_object_data(self.id)
			assert typename == self.type, _assertion_msg_format % (self.id, typename, self.type)
		else:
			super(Object,self)._set_cache_(attr)
		
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
	
	def _set_cache_(self, attr):
		if attr in IndexObject.__slots__:
			# they cannot be retrieved lateron ( not without searching for them )
			raise AttributeError( "path and mode attributes must have been set during %s object creation" % type(self).__name__ )
		else:
			super(IndexObject, self)._set_cache_(attr)
	
	@classmethod
	def _mode_str_to_int(cls, modestr):
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
	  
		
class Diffable(object):
	"""
	Common interface for all object that can be diffed against another object of compatible type.
	
	NOTE: 
		Subclasses require a repo member as it is the case for Object instances, for practical 
		reasons we do not derive from Object.
	"""
	__slots__ = tuple()
	
	# subclasses provide additional arguments to the git-diff comamnd by supplynig 
	# them in this tuple
	_diff_args = tuple()
	
	def diff(self, other=None, paths=None, create_patch=False, **kwargs):
		"""
		Creates diffs between two items being trees, trees and index or an 
		index and the working tree.

		``other``
			Is the item to compare us with. 
			If None, we will be compared to the working tree.

		``paths``
			is a list of paths or a single path to limit the diff to.
			It will only include at least one of the givne path or paths.

		``create_patch``
			If True, the returned Diff contains a detailed patch that if applied
			makes the self to other. Patches are somwhat costly as blobs have to be read
			and diffed.

		``kwargs``
			Additional arguments passed to git-diff, such as 
			R=True to swap both sides of the diff.

		Returns
			git.DiffIndex
			
		Note
			Rename detection will only work if create_patch is True
		"""
		# import it in a retared fashion to avoid dependency cycle
		from git.diff import Diff
		
		args = list(self._diff_args[:])
		args.append( "--abbrev=40" )		# we need full shas
		args.append( "--full-index" )		# get full index paths, not only filenames
		
		if create_patch:
			args.append("-p")
			args.append("-M") # check for renames
		else:
			args.append("--raw")
		
		paths = paths or []
		if paths:
			paths.insert(0, "--")

		if other is not None:
			args.insert(0, other)
		
		args.insert(0,self)
		args.extend(paths)
		
		kwargs['as_process'] = True
		proc = self.repo.git.diff(*args, **kwargs)
		
		diff_method = Diff._index_from_raw_format
		if create_patch:
			diff_method = Diff._index_from_patch_format
		return diff_method(self.repo, proc.stdout)
		

