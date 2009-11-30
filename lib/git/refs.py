# refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all ref based objects """

import os
from objects import Object, Commit
from objects.utils import get_object_type_by_name
from utils import LazyMixin, Iterable, join_path, join_path_native, to_native_path_linux


class SymbolicReference(object):                           
	"""
	Represents a special case of a reference such that this reference is symbolic.
	It does not point to a specific commit, but to another Head, which itself 
	specifies a commit.
	
	A typical example for a symbolic reference is HEAD.
	"""
	__slots__ = ("repo", "path")
	_common_path_default = ""
	_id_attribute_ = "name"
	
	def __init__(self, repo, path):
		self.repo = repo
		self.path = path
		
	def __str__(self):
		return self.path
		
	def __repr__(self):
		return '<git.%s "%s">' % (self.__class__.__name__, self.path)
		
	def __eq__(self, other):
		return self.path == other.path
		
	def __ne__(self, other):
		return not ( self == other )
		
	def __hash__(self):
		return hash(self.path)
		
	@property
	def name(self):
		"""
		Returns
			In case of symbolic references, the shortest assumable name 
			is the path itself.
		"""
		return self.path	
	
	def _get_path(self):
		return join_path_native(self.repo.path, self.path)
		
	@classmethod
	def _iter_packed_refs(cls, repo):
		"""Returns an iterator yielding pairs of sha1/path pairs for the corresponding
		refs.
		NOTE: The packed refs file will be kept open as long as we iterate"""
		try:
			fp = open(os.path.join(repo.path, 'packed-refs'), 'r')
			for line in fp:
				line = line.strip()
				if not line:
					continue
				if line.startswith('#'):
					if line.startswith('# pack-refs with:') and not line.endswith('peeled'):
						raise TypeError("PackingType of packed-Refs not understood: %r" % line)
					# END abort if we do not understand the packing scheme
					continue
				# END parse comment
				
				# skip dereferenced tag object entries - previous line was actual
				# tag reference for it
				if line[0] == '^':
					continue
				
				yield tuple(line.split(' ', 1))
			# END for each line
		except (OSError,IOError):
			raise StopIteration
		# END no packed-refs file handling 
		# NOTE: Had try-finally block around here to close the fp, 
		# but some python version woudn't allow yields within that.
		# I believe files are closing themselves on destruction, so it is 
		# alright.
		
	def _get_commit(self):
		"""
		Returns:
			Commit object we point to, works for detached and non-detached 
			SymbolicReferences
		"""
		# we partially reimplement it to prevent unnecessary file access
		tokens = None
		try:
			fp = open(self._get_path(), 'r')
			value = fp.read().rstrip()
			fp.close()
			tokens = value.split(" ")
		except (OSError,IOError):
			# Probably we are just packed, find our entry in the packed refs file
			# NOTE: We are not a symbolic ref if we are in a packed file, as these
			# are excluded explictly
			for sha, path in self._iter_packed_refs(self.repo):
				if path != self.path: continue
				tokens = (sha, path)
				break
			# END for each packed ref
		# END handle packed refs
		
		# it is a detached reference
		if self.repo.re_hexsha_only.match(tokens[0]):
			return Commit(self.repo, tokens[0])
		
		# must be a head ! Git does not allow symbol refs to other things than heads
		# Otherwise it would have detached it
		if tokens[0] != "ref:":
			raise ValueError("Failed to parse symbolic refernce: wanted 'ref: <hexsha>', got %r" % value)
		return Head(self.repo, tokens[1]).commit
		
	def _set_commit(self, commit):
		"""
		Set our commit, possibly dereference our symbolic reference first.
		"""
		if self.is_detached:
			return self._set_reference(commit)
			
		# set the commit on our reference
		self._get_reference().commit = commit
	
	commit = property(_get_commit, _set_commit, doc="Query or set commits directly")
		
	def _get_reference(self):
		"""
		Returns
			Reference Object we point to
		"""
		fp = open(self._get_path(), 'r')
		try:
			tokens = fp.readline().rstrip().split(' ')
			if tokens[0] != 'ref:':
				raise TypeError("%s is a detached symbolic reference as it points to %r" % (self, tokens[0]))
			return Reference.from_path(self.repo, tokens[1])
		finally:
			fp.close()
		
	def _set_reference(self, ref):
		"""
		Set ourselves to the given ref. It will stay a symbol if the ref is a Head.
		Otherwise we try to get a commit from it using our interface.
		
		Strings are allowed but will be checked to be sure we have a commit
		"""
		write_value = None
		if isinstance(ref, Head):
			write_value = "ref: %s" % ref.path
		elif isinstance(ref, Commit):
			write_value = ref.sha
		else:
			try:
				write_value = ref.commit.sha
			except AttributeError:
				sha = str(ref)
				try:
					obj = Object.new(self.repo, sha)
					if obj.type != "commit":
						raise TypeError("Invalid object type behind sha: %s" % sha)
					write_value = obj.sha
				except Exception:
					raise ValueError("Could not extract object from %s" % ref)
			# END end try string  
		# END try commit attribute
		
		# if we are writing a ref, use symbolic ref to get the reflog and more
		# checking
		# Otherwise we detach it and have to do it manually
		if write_value.startswith('ref:'):
			self.repo.git.symbolic_ref(self.path, write_value[5:])
			return 
		# END non-detached handling
		
		path = self._get_path()
		directory = os.path.dirname(path)
		if not os.path.isdir(directory):
			os.makedirs(directory)
		
		fp = open(path, "w")
		try:
			fp.write(write_value)
		finally:
			fp.close()
		# END writing
		
	reference = property(_get_reference, _set_reference, doc="Returns the Reference we point to")
	
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
	
	@classmethod
	def from_path(cls, repo, path):
		"""
		Return
			Instance of SymbolicReference or HEAD
			depending on the given path
			
		Note
			It enforces that symbolic refs in git are only found in the 
			root of the .git repository, never within a folder.
		"""
		if not path:
			raise ValueError("Cannot create Symbolic Reference from %r" % path)
		
		if path == 'HEAD':
			return HEAD(repo, path)
		
		if '/' not in path:
			return SymbolicReference(repo, path)
			
		raise ValueError("Could not find symbolic reference type suitable to handle path %r" % path)

	@classmethod
	def _to_full_path(cls, repo, path):
		full_ref_path = path
		if not cls._common_path_default:
			return full_ref_path
		if not path.startswith(cls._common_path_default+"/"):
			full_ref_path = '%s/%s' % (cls._common_path_default, path)
		return full_ref_path
	
	@classmethod
	def delete(cls, repo, path):
		"""Delete the reference at the given path
		
		``repo``
			Repository to delete the reference from
		
		``path``
			Short or full path pointing to the reference, i.e. refs/myreference
			or just "myreference", hence 'refs/' is implied.
		"""
		full_ref_path = cls._to_full_path(repo, path)
		abs_path = os.path.join(repo.path, full_ref_path)
		if os.path.exists(abs_path):
			os.remove(abs_path)
			
	@classmethod
	def _create(cls, repo, path, resolve, reference, force):
		"""internal method used to create a new symbolic reference.
		If resolve is False,, the reference will be taken as is, creating 
		a proper symbolic reference. Otherwise it will be resolved to the 
		corresponding object and a detached symbolic reference will be created
		instead"""
		full_ref_path = cls._to_full_path(repo, path)
		
		abs_ref_path = os.path.join(repo.path, full_ref_path)
		if not force and os.path.isfile(abs_ref_path):
			raise OSError("Reference at %s does already exist" % full_ref_path)
		
		ref = cls(repo, full_ref_path)
		target = reference
		if resolve:
			target = Object.new(repo, reference)
		
		ref.reference = target
		return ref
		
	@classmethod
	def create(cls, repo, path, reference='HEAD', force=False ):
		"""
		Create a new symbolic reference, hence a reference pointing to another 
		reference.
		``repo``
			Repository to create the reference in 
			
		``path``
			full path at which the new symbolic reference is supposed to be 
			created at, i.e. "NEW_HEAD" or "symrefs/my_new_symref"
			
		``reference``
			The reference to which the new symbolic reference should point to
		
		``force``
			if True, force creation even if a symbolic reference with that name already exists.
			Raise OSError otherwise
			
		Returns
			Newly created symbolic Reference
			
		Note
			This does not alter the current HEAD, index or Working Tree
		"""
		return cls._create(repo, path, False, reference, force)
		

class Reference(SymbolicReference, LazyMixin, Iterable):
	"""
	Represents a named reference to any object. Subclasses may apply restrictions though, 
	i.e. Heads can only point to commits.
	"""
	__slots__ = tuple()
	_common_path_default = "refs"
	
	def __init__(self, repo, path):
		"""
		Initialize this instance
		``repo``
			Our parent repository
		
		``path``
			Path relative to the .git/ directory pointing to the ref in question, i.e.
			refs/heads/master
			
		"""
		if not path.startswith(self._common_path_default):
			raise ValueError("Cannot instantiate %s from path %s" % ( self.__class__.__name__, path ))
		super(Reference, self).__init__(repo, path)
		

	def __str__(self):
		return self.name

	def _get_object(self):
		"""
		Returns
			The object our ref currently refers to. Refs can be cached, they will 
			always point to the actual object as it gets re-created on each query
		"""
		# have to be dynamic here as we may be a tag which can point to anything
		# Our path will be resolved to the hexsha which will be used accordingly
		return Object.new(self.repo, self.path)
		
	def _set_object(self, ref):
		"""
		Set our reference to point to the given ref. It will be converted
		to a specific hexsha.
		
		Note: 
			TypeChecking is done by the git command
		"""
		# do it safely by specifying the old value
		self.repo.git.update_ref(self.path, ref, self._get_object().sha)
		
	object = property(_get_object, _set_object, doc="Return the object our ref currently refers to")
		
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
			return self.path		   # could be refs/HEAD
		return '/'.join(tokens[2:])
	
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

		Returns
			git.Reference[]
			
			List is lexigraphically sorted
			The returned objects represent actual subclasses, such as Head or TagReference
		"""
		if common_path is None:
			common_path = cls._common_path_default
		
		rela_paths = set()
		
		# walk loose refs
		# Currently we do not follow links 
		for root, dirs, files in os.walk(join_path_native(repo.path, common_path)):
			for f in files:
				abs_path = to_native_path_linux(join_path(root, f))
				rela_paths.add(abs_path.replace(to_native_path_linux(repo.path) + '/', ""))
			# END for each file in root directory
		# END for each directory to walk
		
		# read packed refs
		for sha, rela_path in cls._iter_packed_refs(repo):
			if rela_path.startswith(common_path):
				rela_paths.add(rela_path)
			# END relative path matches common path
		# END packed refs reading
		
		# return paths in sorted order
		for path in sorted(rela_paths):
			if path.endswith('/HEAD'):
				continue
			# END skip remote heads
			yield cls.from_path(repo, path)
		# END for each sorted relative refpath
		
		
	@classmethod
	def from_path(cls, repo, path):
		"""
		Return
			Instance of type Reference, Head, or Tag
			depending on the given path
		"""
		if not path:
			raise ValueError("Cannot create Reference from %r" % path)
		
		for ref_type in (Head, RemoteReference, TagReference, Reference):
			try:
				return ref_type(repo, path)
			except ValueError:
				pass
			# END exception handling
		# END for each type to try
		raise ValueError("Could not find reference type suitable to handle path %r" % path)
		
	
	@classmethod
	def create(cls, repo, path, commit='HEAD', force=False ):
		"""
		Create a new reference.
		``repo``
			Repository to create the reference in 
			
		``path``
			The relative path of the reference, i.e. 'new_branch' or 
			feature/feature1. The path prefix 'refs/' is implied if not 
			given explicitly
			
		``commit``
			Commit to which the new reference should point, defaults to the 
			current HEAD
		
		``force``
			if True, force creation even if a reference with that  name already exists.
			Raise OSError otherwise
			
		Returns
			Newly created Reference
			
		Note
			This does not alter the current HEAD, index or Working Tree
		"""
		return cls._create(repo, path, True, commit, force)
		
	
class HEAD(SymbolicReference):
	"""
	Special case of a Symbolic Reference as it represents the repository's 
	HEAD reference.
	"""
	_HEAD_NAME = 'HEAD'
	__slots__ = tuple()
	
	def __init__(self, repo, path=_HEAD_NAME):
		if path != self._HEAD_NAME:
			raise ValueError("HEAD instance must point to %r, got %r" % (self._HEAD_NAME, path))
		super(HEAD, self).__init__(repo, path)
	
	
	def reset(self, commit='HEAD', index=True, working_tree = False, 
				paths=None, **kwargs):
		"""
		Reset our HEAD to the given commit optionally synchronizing 
		the index and working tree. The reference we refer to will be set to 
		commit as well.
		
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

		>>> head.commit.sha
		'1c09f116cbc2cb4100fb6935bb162daa4723f455'
	"""
	_common_path_default = "refs/heads"
	
	@classmethod
	def create(cls, repo, path, commit='HEAD', force=False, **kwargs ):
		"""
		Create a new head.
		``repo``
			Repository to create the head in 
			
		``path``
			The name or path of the head, i.e. 'new_branch' or 
			feature/feature1. The prefix refs/heads is implied.
			
		``commit``
			Commit to which the new head should point, defaults to the 
			current HEAD
		
		``force``
			if True, force creation even if branch with that  name already exists.
			
		``**kwargs``
			Additional keyword arguments to be passed to git-branch, i.e.
			track, no-track, l
		
		Returns
			Newly created Head
			
		Note
			This does not alter the current HEAD, index or Working Tree
		"""
		if cls is not Head:
			raise TypeError("Only Heads can be created explicitly, not objects of type %s" % cls.__name__)
		
		args = ( path, commit )
		if force:
			kwargs['f'] = True
		
		repo.git.branch(*args, **kwargs)
		return cls(repo, "%s/%s" % ( cls._common_path_default, path))
			
		
	@classmethod
	def delete(cls, repo, *heads, **kwargs):
		"""
		Delete the given heads
		
		``force``
			If True, the heads will be deleted even if they are not yet merged into
			the main development stream.
			Default False
		"""
		force = kwargs.get("force", False)
		flag = "-d"
		if force:
			flag = "-D"
		repo.git.branch(flag, *heads)
		
	
	def rename(self, new_path, force=False):
		"""
		Rename self to a new path
		
		``new_path``
			Either a simple name or a path, i.e. new_name or features/new_name.
			The prefix refs/heads is implied
			
		``force``
			If True, the rename will succeed even if a head with the target name
			already exists.
			
		Returns
			self
		"""
		flag = "-m"
		if force:
			flag = "-M"
			
		self.repo.git.branch(flag, self, new_path)
		self.path  = "%s/%s" % (self._common_path_default, new_path)
		return self
		
	def checkout(self, force=False, **kwargs):
		"""
		Checkout this head by setting the HEAD to this reference, by updating the index
		to reflect the tree we point to and by updating the working tree to reflect 
		the latest index.
		
		The command will fail if changed working tree files would be overwritten.
		
		``force``
			If True, changes to the index and the working tree will be discarded.
			If False, GitCommandError will be raised in that situation.
			
		``**kwargs``
			Additional keyword arguments to be passed to git checkout, i.e.
			b='new_branch' to create a new branch at the given spot.
		
		Returns
			The active branch after the checkout operation, usually self unless
			a new branch has been created.
		
		Note
			By default it is only allowed to checkout heads - everything else
			will leave the HEAD detached which is allowed and possible, but remains
			a special state that some tools might not be able to handle.
		"""
		args = list()
		kwargs['f'] = force
		if kwargs['f'] == False:
			kwargs.pop('f')
		
		self.repo.git.checkout(self, **kwargs)
		return self.repo.active_branch
		

class TagReference(Reference):
	"""
	Class representing a lightweight tag reference which either points to a commit 
	,a tag object or any other object. In the latter case additional information, 
	like the signature or the tag-creator, is available.
	
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
		
	@classmethod
	def create(cls, repo, path, ref='HEAD', message=None, force=False, **kwargs):
		"""
		Create a new tag reference.
		
		``path``
			The name of the tag, i.e. 1.0 or releases/1.0. 
			The prefix refs/tags is implied
			
		``ref``
			A reference to the object you want to tag. It can be a commit, tree or 
			blob.
			
		``message``
			If not None, the message will be used in your tag object. This will also 
			create an additional tag object that allows to obtain that information, i.e.::
				tagref.tag.message
			
		``force``
			If True, to force creation of a tag even though that tag already exists.
			
		``**kwargs``
			Additional keyword arguments to be passed to git-tag
			
		Returns
			A new TagReference
		"""
		args = ( path, ref )
		if message:
			kwargs['m'] =  message
		if force:
			kwargs['f'] = True
		
		repo.git.tag(*args, **kwargs)
		return TagReference(repo, "%s/%s" % (cls._common_path_default, path))
		
	@classmethod
	def delete(cls, repo, *tags):
		"""
		Delete the given existing tag or tags
		"""
		repo.git.tag("-d", *tags)
		
		
		

		
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
	def remote_head(self):
		"""
		Returns
			Name of the remote head itself, i.e. master.
			
		NOTE: The returned name is usually not qualified enough to uniquely identify
		a branch
		"""
		tokens = self.path.split('/')
		return '/'.join(tokens[3:])
		
	@classmethod
	def delete(cls, repo, *remotes, **kwargs):
		"""
		Delete the given remote references.
		
		Note
			kwargs are given for compatability with the base class method as we 
			should not narrow the signature.
		"""
		repo.git.branch("-d", "-r", *remotes)
