# base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os

class LazyMixin(object):
	lazy_properties = []
	__slots__ = tuple()
	
	def __getattr__(self, attr):
		"""
		Whenever an attribute is requested that we do not know, we allow it 
		to be created and set. Next time the same attribute is reqeusted, it is simply
		returned from our dict/slots.
		"""
		self._set_cache_(attr)
		# will raise in case the cache was not created
		return object.__getattribute__(self, attr)

	def _set_cache_(self, attr):
		""" This method should be overridden in the derived class. 
		It should check whether the attribute named by attr can be created
		and cached. Do nothing if you do not know the attribute or call your subclass
		
		The derived class may create as many additional attributes as it deems 
		necessary in case a git command returns more information than represented 
		in the single attribute."""
		pass
	
		
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
	
	@property
	def id_abbrev(self):
		"""
		Returns
			First 7 bytes of the commit's sha id as an abbreviation of the full string.
		"""
		return self.id[0:7]
	
	@classmethod
	def get_type_by_name(cls, object_type_name):
		"""
		Returns
			type suitable to handle the given object type name.
			Use the type to create new instances.
			
		``object_type_name``
			Member of TYPES
			
		Raises
			ValueError: In case object_type_name is unknown
		"""
		if object_type_name == "commit":
			import commit
			return commit.Commit
		elif object_type_name == "tag":
			import tag
			return tag.TagObject
		elif object_type_name == "blob":
			import blob
			return blob.Blob
		elif object_type_name == "tree":
			import tree
			return tree.Tree
		else:
			raise ValueError("Cannot handle unknown object type: %s" % object_type_name)
		
		
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
		"""
		super(IndexObject, self).__init__(repo, id)
		self.mode = mode
		self.path = path
	
	@property
	def basename(self):
	  """
	  Returns
		  The basename of the IndexObject's file path
	  """
	  return os.path.basename(self.path)
	  
		
class Ref(object):
	"""
	Represents a named reference to any object
	"""
	__slots__ = ("path", "object")
	
	def __init__(self, path, object = None):
		"""
		Initialize this instance
		
		``path``
			Path relative to the .git/ directory pointing to the ref in question, i.e.
			refs/heads/master
			
		``object``
			Object instance, will be retrieved on demand if None
		"""
		self.path = path
		self.object = object
		
	def __str__(self):
		return self.name()
		
	def __repr__(self):
		return '<git.%s "%s">' % (self.__class__.__name__, self.path)
		
	def __eq__(self, other):
		return self.path == other.path and self.object == other.object
		
	def __ne__(self, other):
		return not ( self == other )
		
	def __hash__(self):
		return hash(self.path)
		
	@property
	def name(self):
		"""
		Returns
			Name of this reference
		"""
		return os.path.basename(self.path)
		
	@classmethod
	def find_all(cls, repo, common_path = "refs", **kwargs):
		"""
		Find all refs in the repository

		``repo``
			is the Repo

		``common_path``
			Optional keyword argument to the path which is to be shared by all
			returned Ref objects

		``kwargs``
			Additional options given as keyword arguments, will be passed
			to git-for-each-ref

		Returns
			git.Ref[]
			
			List is sorted by committerdate
			The returned objects are compatible to the Ref base, but represent the 
			actual type, such as Head or Tag
		"""

		options = {'sort': "committerdate",
				   'format': "%(refname)%00%(objectname)%00%(objecttype)%00%(objectsize)"}
				   
		options.update(kwargs)

		output = repo.git.for_each_ref(common_path, **options)
		return cls.list_from_string(repo, output)

	@classmethod
	def list_from_string(cls, repo, text):
		"""
		Parse out ref information into a list of Ref compatible objects

		``repo``
			is the Repo
		``text``
			is the text output from the git-for-each-ref command

		Returns
			git.Ref[]
			
			list of Ref objects
		"""
		heads = []

		for line in text.splitlines():
			heads.append(cls.from_string(repo, line))

		return heads

	@classmethod
	def from_string(cls, repo, line):
		"""
		Create a new Ref instance from the given string.

		``repo``
			is the Repo

		``line``
			is the formatted ref information

		Format::
		
			name: [a-zA-Z_/]+
			<null byte>
			id: [0-9A-Fa-f]{40}

		Returns
			git.Head
		"""
		full_path, hexsha, type_name, object_size = line.split("\x00")
		obj = Object.get_type_by_name(type_name)(repo, hexsha)
		obj.size = object_size
		return cls(full_path, obj)
