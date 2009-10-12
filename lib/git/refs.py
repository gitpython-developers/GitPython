# refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing all ref based objects
"""
from objects.base import Object
from objects.util import get_object_type_by_name

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
		return cls._list_from_string(repo, output)

	@classmethod
	def _list_from_string(cls, repo, text):
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
			heads.append(cls._from_string(repo, line))

		return heads

	@classmethod
	def _from_string(cls, repo, line):
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
		obj = get_object_type_by_name(type_name)(repo, hexsha)
		obj.size = object_size
		return cls(full_path, obj)
		

class Head(Ref):
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

	@property
	def commit(self):
		"""
		Returns
			Commit object the head points to
		"""
		return self.object
		
	@classmethod
	def find_all(cls, repo, common_path = "refs/heads", **kwargs):
		"""
		Returns
			git.Head[]
			
		For more documentation, please refer to git.base.Ref.find_all
		"""
		return super(Head,cls).find_all(repo, common_path, **kwargs)

	def __repr__(self):
		return '<git.Head "%s">' % self.name
		
		

class TagRef(Ref):
	"""
	Class representing a lightweight tag reference which either points to a commit 
	or to a tag object. In the latter case additional information, like the signature
	or the tag-creator, is available.
	
	This tag object will always point to a commit object, but may carray additional
	information in a tag object::
	
	 tagref = TagRef.find_all(repo)[0]
	 print tagref.commit.message
	 if tagref.tag is not None:
		print tagref.tag.message
	"""
	
	__slots__ = "tag"
	
	def __init__(self, path, commit_or_tag):
		"""
		Initialize a newly instantiated Tag

		``path``
			is the full path to the tag

		``commit_or_tag``
			is the Commit or TagObject that this tag ref points to
		"""
		super(TagRef, self).__init__(path, commit_or_tag)
		self.tag = None
		
		if commit_or_tag.type == "tag":
			self.tag = commit_or_tag
		# END tag object handling 
	
	@property
	def commit(self):
		"""
		Returns
			Commit object the tag ref points to
		"""
		if self.object.type == "commit":
			return self.object
		# it is a tag object
		return self.object.object

	@classmethod
	def find_all(cls, repo, common_path = "refs/tags", **kwargs):
		"""
		Returns
			git.Tag[]
			
		For more documentation, please refer to git.base.Ref.find_all
		"""
		return super(TagRef,cls).find_all(repo, common_path, **kwargs)
		
		
# provide an alias
Tag = TagRef
