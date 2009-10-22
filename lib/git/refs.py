# refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing all ref based objects
"""
import os
from objects.base import Object
from objects.utils import get_object_type_by_name
from utils import LazyMixin, Iterable

class Reference(LazyMixin, Iterable):
	"""
	Represents a named reference to any object
	"""
	__slots__ = ("repo", "path")
	_common_path_default = "refs"
	_id_attribute_ = "name"
	
	def __init__(self, repo, path, object = None):
		"""
		Initialize this instance
		``repo``
			Our parent repository
		
		``path``
			Path relative to the .git/ directory pointing to the ref in question, i.e.
			refs/heads/master
			
		``object``
			Object instance, will be retrieved on demand if None
		"""
		if not path.startswith(self._common_path_default):
			raise ValueError("Cannot instantiate %s Reference from path %s" % ( self.__class__.__name__, path ))
			
		self.repo = repo
		self.path = path
		if object is not None:
			self.object = object
		
	def __str__(self):
		return self.name
		
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
			(shortest) Name of this reference - it may contain path components
		"""
		# first two path tokens are can be removed as they are 
		# refs/heads or refs/tags or refs/remotes
		tokens = self.path.split('/')
		if len(tokens) < 3:
			return self.path	# could be refs/HEAD
		
		return '/'.join(tokens[2:])
	
	@property
	def object(self):
		"""
		Returns
			The object our ref currently refers to. Refs can be cached, they will 
			always point to the actual object as it gets re-created on each query
		"""
		# have to be dynamic here as we may be a tag which can point to anything
		# Our path will be resolved to the hexsha which will be used accordingly
		return Object.new(self.repo, self.path)
		
	@property
	def commit(self):
		"""
		Returns
			Commit object the head points to
		"""
		commit = self.object
		if commit.type != "commit":
			raise TypeError("Object of reference %s did not point to a commit" % self)
		return commit
	
	@classmethod
	def iter_items(cls, repo, common_path = None, **kwargs):
		"""
		Find all refs in the repository

		``repo``
			is the Repo

		``common_path``
			Optional keyword argument to the path which is to be shared by all
			returned Ref objects.
			Defaults to class specific portion if None assuring that only 
			refs suitable for the actual class are returned.

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
		
		if common_path is None:
			common_path = cls._common_path_default
		
		options.update(kwargs)

		output = repo.git.for_each_ref(common_path, **options)
		return cls._iter_from_stream(repo, iter(output.splitlines()))
		
	@classmethod
	def from_path(cls, repo, path):
		"""
		Return
			Instance of type Reference, Head, Tag, SymbolicReference or HEAD
			depending on the given path
		"""
		if path == 'HEAD':
			return HEAD(repo, path)
		
		if '/' not in path:
			return SymbolicReference(repo, path)
			
		for ref_type in (Head, RemoteReference, TagReference, Reference):
			try:
				return ref_type(repo, path)
			except ValueError:
				pass
			# END exception handling
		# END for each type to try
		raise ValueError("Could not find reference type suitable to handle path %r" % path)
		

	@classmethod
	def _iter_from_stream(cls, repo, stream):
		""" Parse out ref information into a list of Ref compatible objects
		Returns git.Ref[] list of Ref objects """
		heads = []

		for line in stream:
			heads.append(cls._from_string(repo, line))

		return heads

	@classmethod
	def _from_string(cls, repo, line):
		""" Create a new Ref instance from the given string.
		Format
			name: [a-zA-Z_/]+
			<null byte>
			id: [0-9A-Fa-f]{40}
		Returns git.Head """
		full_path, hexsha, type_name, object_size = line.split("\x00")
		
		# No, we keep the object dynamic by allowing it to be retrieved by
		# our path on demand - due to perstent commands it is fast.
		# This reduces the risk that the object does not match 
		# the changed ref anymore in case it changes in the meanwhile
		return cls(repo, full_path)
		
		# obj = get_object_type_by_name(type_name)(repo, hexsha)
		# obj.size = object_size
		# return cls(repo, full_path, obj)
		

class SymbolicReference(object):
	"""
	Represents a special case of a reference such that this reference is symbolic.
	It does not point to a specific commit, but to another Head, which itself 
	specifies a commit.
	
	A typical example for a symbolic reference is HEAD.
	"""
	__slots__ = ("repo", "name")
	
	def __init__(self, repo, name):
		if '/' in name:
			raise ValueError("SymbolicReferences are not located within a directory, got %s" % name)
		self.repo = repo
		self.name = name
		
	def __str__(self):
		return self.name
		
	def __repr__(self):
		return '<git.%s "%s">' % (self.__class__.__name__, self.name)
		
	def __eq__(self, other):
		return self.name == other.name
		
	def __ne__(self, other):
		return not ( self == other )
		
	def __hash__(self):
		return hash(self.name)
		
	@property
	def reference(self):
		"""
		Returns
			Reference Object we point to
		"""
		fp = open(os.path.join(self.repo.path, self.name), 'r')
		try:
			tokens = fp.readline().rstrip().split(' ')
			if tokens[0] != 'ref:':
				raise TypeError("%s is a detached symbolic reference as it points to %r" % tokens[0])
			return Reference.from_path(self.repo, tokens[1])
		finally:
			fp.close()
		
	# alias
	ref = reference
		
	@property
	def is_detached(self):
		"""
		Returns
			True if we are a detached reference, hence we point to a specific commit
			instead to another reference
		"""
		try:
			self.reference
			return False
		except TypeError:
			return True
	
	
class HEAD(SymbolicReference):
	"""
	Special case of a Symbolic Reference as it represents the repository's 
	HEAD reference.
	"""
	__slots__ = tuple()
	
	def __init__(self, repo, name):
		if name != 'HEAD':
			raise ValueError("HEAD instance must point to 'HEAD', got %s" % name)
		super(HEAD, self).__init__(repo, name)
	
	
	def reset(self, commit='HEAD', index=True, working_tree = False, 
				paths=None, **kwargs):
		"""
		Reset our HEAD to the given commit optionally synchronizing 
		the index and working tree.
		
		``commit``
			Commit object, Reference Object or string identifying a revision we 
			should reset HEAD to.
			
		``index``
			If True, the index will be set to match the given commit. Otherwise
			it will not be touched.
		
		``working_tree``
			If True, the working tree will be forcefully adjusted to match the given
			commit, possibly overwriting uncommitted changes without warning.
			If working_tree is True, index must be true as well
		
		``paths``
			Single path or list of paths relative to the git root directory
			that are to be reset. This allow to partially reset individual files.
		
		``kwargs``
			Additional arguments passed to git-reset. 
		
		Returns
			self
		"""
		mode = "--soft"
		if index:
			mode = "--mixed"
			
		if working_tree:
			mode = "--hard"
			if not index:
				raise ValueError( "Cannot reset the working tree if the index is not reset as well") 
		# END working tree handling
		
		self.repo.git.reset(mode, commit, paths, **kwargs)
		
		return self
	

class Head(Reference):
	"""
	A Head is a named reference to a Commit. Every Head instance contains a name
	and a Commit object.

	Examples::

		>>> repo = Repo("/path/to/repo")
		>>> head = repo.heads[0]

		>>> head.name		
		'master'

		>>> head.commit		
		<git.Commit "1c09f116cbc2cb4100fb6935bb162daa4723f455">

		>>> head.commit.id
		'1c09f116cbc2cb4100fb6935bb162daa4723f455'
	"""
	_common_path_default = "refs/heads"
	

class TagReference(Reference):
	"""
	Class representing a lightweight tag reference which either points to a commit 
	or to a tag object. In the latter case additional information, like the signature
	or the tag-creator, is available.
	
	This tag object will always point to a commit object, but may carray additional
	information in a tag object::
	
	 tagref = TagReference.list_items(repo)[0]
	 print tagref.commit.message
	 if tagref.tag is not None:
		print tagref.tag.message
	"""
	
	__slots__ = tuple()
	_common_path_default = "refs/tags"
	
	@property
	def commit(self):
		"""
		Returns
			Commit object the tag ref points to
		"""
		if self.object.type == "commit":
			return self.object
		elif self.object.type == "tag":
			# it is a tag object which carries the commit as an object - we can point to anything
			return self.object.object
		else:
			raise ValueError( "Tag %s points to a Blob or Tree - have never seen that before" % self )  

	@property
	def tag(self):
		"""
		Returns
			Tag object this tag ref points to or None in case 
			we are a light weight tag
		"""
		if self.object.type == "tag":
			return self.object
		return None

		
# provide an alias
Tag = TagReference

class RemoteReference(Head):
	"""
	Represents a reference pointing to a remote head.
	"""
	_common_path_default = "refs/remotes"
	
	@property
	def remote_name(self):
		"""
		Returns
			Name of the remote we are a reference of, such as 'origin' for a reference
			named 'origin/master'
		"""
		tokens = self.path.split('/')
		# /refs/remotes/<remote name>/<branch_name>
		return tokens[2]
		
	@property
	def remote_branch(self):
		"""
		Returns
			Name of the remote branch itself, i.e. master.
			
		NOTE: The returned name is usually not qualified enough to uniquely identify
		a branch
		"""
		tokens = self.path.split('/')
		return '/'.join(tokens[3:])
