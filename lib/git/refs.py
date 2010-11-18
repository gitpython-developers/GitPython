# refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all ref based objects """

import os
from objects import (
						Object, 
						Commit
					)
from objects.util import get_object_type_by_name
from util import (
					LazyMixin, 
					Iterable, 
					join_path, 
					join_path_native, 
					to_native_path_linux
					)

from gitdb.util import (
							join, 
							dirname,
							isdir,
							exists,
							isfile,
							rename,
							hex_to_bin
						)

from config import 	(
					GitConfigParser,
					SectionConstraint
					)

from exc import GitCommandError

__all__ = ("SymbolicReference", "Reference", "HEAD", "Head", "TagReference", 
			"RemoteReference", "Tag" )

class SymbolicReference(object):
	"""Represents a special case of a reference such that this reference is symbolic.
	It does not point to a specific commit, but to another Head, which itself 
	specifies a commit.
	
	A typical example for a symbolic reference is HEAD."""
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
		:return:
			In case of symbolic references, the shortest assumable name 
			is the path itself."""
		return self.path
	
	def _abs_path(self):
		return join_path_native(self.repo.git_dir, self.path)
		
	@classmethod
	def _get_packed_refs_path(cls, repo):
		return join(repo.git_dir, 'packed-refs')
		
	@classmethod
	def _iter_packed_refs(cls, repo):
		"""Returns an iterator yielding pairs of sha1/path pairs for the corresponding refs.
		:note: The packed refs file will be kept open as long as we iterate"""
		try:
			fp = open(cls._get_packed_refs_path(repo), 'r')
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
		
	@classmethod
	def dereference_recursive(cls, repo, ref_path):
		"""
		:return: hexsha stored in the reference at the given ref_path, recursively dereferencing all
			intermediate references as required
		:param repo: the repository containing the reference at ref_path"""
		while True:
			ref = cls(repo, ref_path)
			hexsha, ref_path = ref._get_ref_info()
			if hexsha is not None:
				return hexsha
		# END recursive dereferencing
		
	def _get_ref_info(self):
		"""Return: (sha, target_ref_path) if available, the sha the file at 
		rela_path points to, or None. target_ref_path is the reference we 
		point to, or None"""
		tokens = None
		try:
			fp = open(self._abs_path(), 'r')
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
		
		if tokens is None:
			raise ValueError("Reference at %r does not exist" % self.path)
		
		# is it a reference ?
		if tokens[0] == 'ref:':
			return (None, tokens[1])
			
		# its a commit
		if self.repo.re_hexsha_only.match(tokens[0]):
			return (tokens[0], None)
			
		raise ValueError("Failed to parse reference information from %r" % self.path)
		
	def _get_commit(self):
		"""
		:return:
			Commit object we point to, works for detached and non-detached 
			SymbolicReferences"""
		# we partially reimplement it to prevent unnecessary file access
		hexsha, target_ref_path = self._get_ref_info()
		
		# it is a detached reference
		if hexsha:
			return Commit(self.repo, hex_to_bin(hexsha))
		
		return self.from_path(self.repo, target_ref_path).commit
		
	def _set_commit(self, commit):
		"""Set our commit, possibly dereference our symbolic reference first.
		If the reference does not exist, it will be created"""
		is_detached = True
		try:
			is_detached = self.is_detached
		except ValueError:
			pass
		# END handle non-existing ones
		if is_detached:
			return self._set_reference(commit)
			
		# set the commit on our reference
		self._get_reference().commit = commit
	
	commit = property(_get_commit, _set_commit, doc="Query or set commits directly")
		
	def _get_reference(self):
		""":return: Reference Object we point to"""
		sha, target_ref_path = self._get_ref_info()
		if target_ref_path is None:
			raise TypeError("%s is a detached symbolic reference as it points to %r" % (self, sha))
		return self.from_path(self.repo, target_ref_path)
		
	def _set_reference(self, ref):
		"""Set ourselves to the given ref. It will stay a symbol if the ref is a Reference.
		Otherwise we try to get a commit from it using our interface.
		
		Strings are allowed but will be checked to be sure we have a commit"""
		write_value = None
		if isinstance(ref, SymbolicReference):
			write_value = "ref: %s" % ref.path
		elif isinstance(ref, Commit):
			write_value = ref.hexsha
		else:
			try:
				write_value = ref.commit.hexsha
			except AttributeError:
				try:
					obj = self.repo.rev_parse(ref+"^{}")	# optionally deref tags
					if obj.type != "commit":
						raise TypeError("Invalid object type behind sha: %s" % sha)
					write_value = obj.hexsha
				except Exception:
					raise ValueError("Could not extract object from %s" % ref)
			# END end try string  
		# END try commit attribute
		
		# maintain the orig-head if we are currently checked-out
		head = HEAD(self.repo)
		try:
			if head.ref == self:
				try:
					# TODO: implement this atomically, if we fail below, orig_head is at an incorrect spot
					# Enforce the creation of ORIG_HEAD
					SymbolicReference.create(self.repo, head.orig_head().name, self.commit, force=True)
				except ValueError:
					pass
				#END exception handling
			# END if we are checked-out
		except TypeError:
			pass
		# END handle detached heads
		
		# if we are writing a ref, use symbolic ref to get the reflog and more
		# checking
		# Otherwise we detach it and have to do it manually. Besides, this works
		# recursively automaitcally, but should be replaced with a python implementation
		# soon
		if write_value.startswith('ref:'):
			self.repo.git.symbolic_ref(self.path, write_value[5:])
			return
		# END non-detached handling
		
		path = self._abs_path()
		directory = dirname(path)
		if not isdir(directory):
			os.makedirs(directory)
		
		fp = open(path, "wb")
		try:
			fp.write(write_value)
		finally:
			fp.close()
		# END writing
	

	# aliased reference
	reference = property(_get_reference, _set_reference, doc="Returns the Reference we point to")
	ref = reference
		
	def is_valid(self):
		"""
		:return:
			True if the reference is valid, hence it can be read and points to 
			a valid object or reference."""
		try:
			self.commit
		except (OSError, ValueError):
			return False
		else:
			return True
		
	@property
	def is_detached(self):
		"""
		:return:
			True if we are a detached reference, hence we point to a specific commit
			instead to another reference"""
		try:
			self.reference
			return False
		except TypeError:
			return True
	

	@classmethod
	def to_full_path(cls, path):
		"""
		:return: string with a full repository-relative path which can be used to initialize 
			a Reference instance, for instance by using ``Reference.from_path``"""
		if isinstance(path, SymbolicReference):
			path = path.path
		full_ref_path = path
		if not cls._common_path_default:
			return full_ref_path
		if not path.startswith(cls._common_path_default+"/"):
			full_ref_path = '%s/%s' % (cls._common_path_default, path)
		return full_ref_path
	
	@classmethod
	def delete(cls, repo, path):
		"""Delete the reference at the given path
		
		:param repo:
			Repository to delete the reference from
		
		:param path:
			Short or full path pointing to the reference, i.e. refs/myreference
			or just "myreference", hence 'refs/' is implied.
			Alternatively the symbolic reference to be deleted"""
		full_ref_path = cls.to_full_path(path)
		abs_path = join(repo.git_dir, full_ref_path)
		if exists(abs_path):
			os.remove(abs_path)
		else:
			# check packed refs
			pack_file_path = cls._get_packed_refs_path(repo)
			try:
				reader = open(pack_file_path)
			except (OSError,IOError):
				pass # it didnt exist at all
			else:
				new_lines = list()
				made_change = False
				dropped_last_line = False
				for line in reader:
					# keep line if it is a comment or if the ref to delete is not 
					# in the line
					# If we deleted the last line and this one is a tag-reference object, 
					# we drop it as well
					if ( line.startswith('#') or full_ref_path not in line ) and \
						( not dropped_last_line or dropped_last_line and not line.startswith('^') ):
						new_lines.append(line)
						dropped_last_line = False
						continue
					# END skip comments and lines without our path
					
					# drop this line
					made_change = True
					dropped_last_line = True
				# END for each line in packed refs
				reader.close()
				
				# write the new lines
				if made_change:
					open(pack_file_path, 'w').writelines(new_lines)
			# END open exception handling
		# END handle deletion
			
	@classmethod
	def _create(cls, repo, path, resolve, reference, force):
		"""internal method used to create a new symbolic reference.
		If resolve is False,, the reference will be taken as is, creating 
		a proper symbolic reference. Otherwise it will be resolved to the 
		corresponding object and a detached symbolic reference will be created
		instead"""
		full_ref_path = cls.to_full_path(path)
		abs_ref_path = join(repo.git_dir, full_ref_path)
		
		# figure out target data
		target = reference
		if resolve:
			target = repo.rev_parse(str(reference))
			
		if not force and isfile(abs_ref_path):
			target_data = str(target)
			if isinstance(target, SymbolicReference):
				target_data = target.path
			if not resolve:
				target_data = "ref: " + target_data
			if open(abs_ref_path, 'rb').read().strip() != target_data:
				raise OSError("Reference at %s does already exist" % full_ref_path)
		# END no force handling
		
		ref = cls(repo, full_ref_path)
		ref.reference = target
		return ref
		
	@classmethod
	def create(cls, repo, path, reference='HEAD', force=False ):
		"""Create a new symbolic reference, hence a reference pointing to another reference.
		
		:param repo:
			Repository to create the reference in 
			
		:param path:
			full path at which the new symbolic reference is supposed to be 
			created at, i.e. "NEW_HEAD" or "symrefs/my_new_symref"
			
		:param reference:
			The reference to which the new symbolic reference should point to
		
		:param force:
			if True, force creation even if a symbolic reference with that name already exists.
			Raise OSError otherwise
			
		:return: Newly created symbolic Reference
			
		:raise OSError:
			If a (Symbolic)Reference with the same name but different contents
			already exists.
		
		:note: This does not alter the current HEAD, index or Working Tree"""
		return cls._create(repo, path, False, reference, force)
	
	def rename(self, new_path, force=False):
		"""Rename self to a new path
		
		:param new_path:
			Either a simple name or a full path, i.e. new_name or features/new_name.
			The prefix refs/ is implied for references and will be set as needed.
			In case this is a symbolic ref, there is no implied prefix
			
		:param force:
			If True, the rename will succeed even if a head with the target name
			already exists. It will be overwritten in that case
			
		:return: self
		:raise OSError: In case a file at path but a different contents already exists """
		new_path = self.to_full_path(new_path)
		if self.path == new_path:
			return self
		
		new_abs_path = join(self.repo.git_dir, new_path)
		cur_abs_path = join(self.repo.git_dir, self.path)
		if isfile(new_abs_path):
			if not force:
				# if they point to the same file, its not an error
				if open(new_abs_path,'rb').read().strip() != open(cur_abs_path,'rb').read().strip():
					raise OSError("File at path %r already exists" % new_abs_path)
				# else: we could remove ourselves and use the otherone, but 
				# but clarity we just continue as usual
			# END not force handling
			os.remove(new_abs_path)
		# END handle existing target file
		
		dname = dirname(new_abs_path)
		if not isdir(dname):
			os.makedirs(dname)
		# END create directory
		
		rename(cur_abs_path, new_abs_path)
		self.path = new_path
		
		return self
		
	@classmethod
	def _iter_items(cls, repo, common_path = None):
		if common_path is None:
			common_path = cls._common_path_default
		rela_paths = set()
		
		# walk loose refs
		# Currently we do not follow links 
		for root, dirs, files in os.walk(join_path_native(repo.git_dir, common_path)):
			if 'refs/' not in root: # skip non-refs subfolders
				refs_id = [ i for i,d in enumerate(dirs) if d == 'refs' ]
				if refs_id:
					dirs[0:] = ['refs']
			# END prune non-refs folders
			
			for f in files:
				abs_path = to_native_path_linux(join_path(root, f))
				rela_paths.add(abs_path.replace(to_native_path_linux(repo.git_dir) + '/', ""))
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
			try:
				yield cls.from_path(repo, path)
			except ValueError:
				continue
		# END for each sorted relative refpath
		
	@classmethod
	def iter_items(cls, repo, common_path = None):
		"""Find all refs in the repository

		:param repo: is the Repo

		:param common_path:
			Optional keyword argument to the path which is to be shared by all
			returned Ref objects.
			Defaults to class specific portion if None assuring that only 
			refs suitable for the actual class are returned.

		:return:
			git.SymbolicReference[], each of them is guaranteed to be a symbolic
			ref which is not detached.
			
			List is lexigraphically sorted
			The returned objects represent actual subclasses, such as Head or TagReference"""
		return ( r for r in cls._iter_items(repo, common_path) if r.__class__ == SymbolicReference or not r.is_detached )
		
	@classmethod
	def from_path(cls, repo, path):
		"""
		:param path: full .git-directory-relative path name to the Reference to instantiate
		:note: use to_full_path() if you only have a partial path of a known Reference Type
		:return:
			Instance of type Reference, Head, or Tag
			depending on the given path"""
		if not path:
			raise ValueError("Cannot create Reference from %r" % path)
		
		for ref_type in (HEAD, Head, RemoteReference, TagReference, Reference, SymbolicReference):
			try:
				instance = ref_type(repo, path)
				if instance.__class__ == SymbolicReference and instance.is_detached:
					raise ValueError("SymbolRef was detached, we drop it")
				return instance
			except ValueError:
				pass
			# END exception handling
		# END for each type to try
		raise ValueError("Could not find reference type suitable to handle path %r" % path)
		

class Reference(SymbolicReference, LazyMixin, Iterable):
	"""Represents a named reference to any object. Subclasses may apply restrictions though, 
	i.e. Heads can only point to commits."""
	__slots__ = tuple()
	_common_path_default = "refs"
	
	def __init__(self, repo, path):
		"""Initialize this instance
		:param repo: Our parent repository
		
		:param path:
			Path relative to the .git/ directory pointing to the ref in question, i.e.
			refs/heads/master"""
		if not path.startswith(self._common_path_default+'/'):
			raise ValueError("Cannot instantiate %r from path %s" % ( self.__class__.__name__, path ))
		super(Reference, self).__init__(repo, path)
		

	def __str__(self):
		return self.name

	def _get_object(self):
		"""
		:return:
			The object our ref currently refers to. Refs can be cached, they will 
			always point to the actual object as it gets re-created on each query"""
		# have to be dynamic here as we may be a tag which can point to anything
		# Our path will be resolved to the hexsha which will be used accordingly
		return Object.new_from_sha(self.repo, hex_to_bin(self.dereference_recursive(self.repo, self.path)))
		
	def _set_object(self, ref):
		"""
		Set our reference to point to the given ref. It will be converted
		to a specific hexsha.
		If the reference does not exist, it will be created.
		
		:note: 
			TypeChecking is done by the git command"""
		abs_path = self._abs_path()
		existed = True
		if not isfile(abs_path):
			existed = False
			open(abs_path, 'wb').write(Object.NULL_HEX_SHA)
		# END quick create 
		
		# do it safely by specifying the old value
		try:
			self.repo.git.update_ref(self.path, ref, (existed and self._get_object().hexsha) or None)
		except:
			if not existed:
				os.remove(abs_path)
			# END remove file on error if it didn't exist before
			raise
		# END exception handling
		
	object = property(_get_object, _set_object, doc="Return the object our ref currently refers to")
		
	@property
	def name(self):
		""":return: (shortest) Name of this reference - it may contain path components"""
		# first two path tokens are can be removed as they are 
		# refs/heads or refs/tags or refs/remotes
		tokens = self.path.split('/')
		if len(tokens) < 3:
			return self.path		   # could be refs/HEAD
		return '/'.join(tokens[2:])
	
	
	@classmethod
	def create(cls, repo, path, commit='HEAD', force=False ):
		"""Create a new reference.
		
		:param repo: Repository to create the reference in 
		:param path:
			The relative path of the reference, i.e. 'new_branch' or 
			feature/feature1. The path prefix 'refs/' is implied if not 
			given explicitly
			
		:param commit:
			Commit to which the new reference should point, defaults to the 
			current HEAD
			
		:param force:
			if True, force creation even if a reference with that  name already exists.
			Raise OSError otherwise
			
		:return: Newly created Reference
			
		:note: This does not alter the current HEAD, index or Working Tree"""
		return cls._create(repo, path, True, commit, force)
	
	@classmethod	
	def iter_items(cls, repo, common_path = None):
		"""Equivalent to SymbolicReference.iter_items, but will return non-detached
		references as well."""
		return cls._iter_items(repo, common_path)
	
	
class HEAD(SymbolicReference):
	"""Special case of a Symbolic Reference as it represents the repository's 
	HEAD reference."""
	_HEAD_NAME = 'HEAD'
	_ORIG_HEAD_NAME = 'ORIG_HEAD'
	__slots__ = tuple()
	
	def __init__(self, repo, path=_HEAD_NAME):
		if path != self._HEAD_NAME:
			raise ValueError("HEAD instance must point to %r, got %r" % (self._HEAD_NAME, path))
		super(HEAD, self).__init__(repo, path)
	
	def orig_head(self):
		""":return: SymbolicReference pointing at the ORIG_HEAD, which is maintained 
		to contain the previous value of HEAD"""
		return SymbolicReference(self.repo, self._ORIG_HEAD_NAME)
		
	def _set_reference(self, ref):
		"""If someone changes the reference through us, we must manually update 
		the ORIG_HEAD if we are detached. The underlying implementation can only
		handle un-detached heads as it has to check whether the current head 
		is the checked-out one"""
		if self.is_detached:
			prev_commit = self.commit
			super(HEAD, self)._set_reference(ref)
			SymbolicReference.create(self.repo, self._ORIG_HEAD_NAME, prev_commit, force=True)
		else:
			super(HEAD, self)._set_reference(ref)
		# END handle detached mode
		
	# aliased reference
	reference = property(SymbolicReference._get_reference, _set_reference, doc="Returns the Reference we point to")
	ref = reference
	
	def reset(self, commit='HEAD', index=True, working_tree = False, 
				paths=None, **kwargs):
		"""Reset our HEAD to the given commit optionally synchronizing 
		the index and working tree. The reference we refer to will be set to 
		commit as well.
		
		:param commit:
			Commit object, Reference Object or string identifying a revision we 
			should reset HEAD to.
			
		:param index:
			If True, the index will be set to match the given commit. Otherwise
			it will not be touched.
		
		:param working_tree:
			If True, the working tree will be forcefully adjusted to match the given
			commit, possibly overwriting uncommitted changes without warning.
			If working_tree is True, index must be true as well
		
		:param paths:
			Single path or list of paths relative to the git root directory
			that are to be reset. This allows to partially reset individual files.
		
		:param kwargs:
			Additional arguments passed to git-reset. 
		
		:return: self"""
		mode = "--soft"
		add_arg = None
		if index:
			mode = "--mixed"
			
			# it appears, some git-versions declare mixed and paths deprecated
			# see http://github.com/Byron/GitPython/issues#issue/2
			if paths:
				mode = None
			# END special case
		# END handle index
			
		if working_tree:
			mode = "--hard"
			if not index:
				raise ValueError( "Cannot reset the working tree if the index is not reset as well")
			
		# END working tree handling
		
		if paths:
			add_arg = "--"
		# END nicely separate paths from rest
		
		try:
			self.repo.git.reset(mode, commit, add_arg, paths, **kwargs)
		except GitCommandError, e:
			# git nowadays may use 1 as status to indicate there are still unstaged
			# modifications after the reset
			if e.status != 1:
				raise
		# END handle exception
		
		return self
	

class Head(Reference):
	"""A Head is a named reference to a Commit. Every Head instance contains a name
	and a Commit object.

	Examples::

		>>> repo = Repo("/path/to/repo")
		>>> head = repo.heads[0]

		>>> head.name
		'master'

		>>> head.commit
		<git.Commit "1c09f116cbc2cb4100fb6935bb162daa4723f455">

		>>> head.commit.hexsha
		'1c09f116cbc2cb4100fb6935bb162daa4723f455'"""
	_common_path_default = "refs/heads"
	k_config_remote = "remote"
	k_config_remote_ref = "merge"			# branch to merge from remote
	
	@classmethod
	def create(cls, repo, path, commit='HEAD', force=False, **kwargs):
		"""Create a new head.
		:param repo: Repository to create the head in 
		:param path:
			The name or path of the head, i.e. 'new_branch' or 
			feature/feature1. The prefix refs/heads is implied.
			
		:param commit:
			Commit to which the new head should point, defaults to the 
			current HEAD
			
		:param force:
			if True, force creation even if branch with that  name already exists.
			
		:param kwargs:
			Additional keyword arguments to be passed to git-branch, i.e.
			track, no-track, l
			
		:return: Newly created Head
		:note: This does not alter the current HEAD, index or Working Tree"""
		if cls is not Head:
			raise TypeError("Only Heads can be created explicitly, not objects of type %s" % cls.__name__)
		
		args = ( path, commit )
		if force:
			kwargs['f'] = True
		
		repo.git.branch(*args, **kwargs)
		return cls(repo, "%s/%s" % ( cls._common_path_default, path))
			
		
	@classmethod
	def delete(cls, repo, *heads, **kwargs):
		"""Delete the given heads
		:param force:
			If True, the heads will be deleted even if they are not yet merged into
			the main development stream.
			Default False"""
		force = kwargs.get("force", False)
		flag = "-d"
		if force:
			flag = "-D"
		repo.git.branch(flag, *heads)
		
		
	def set_tracking_branch(self, remote_reference):
		"""Configure this branch to track the given remote reference. This will alter
		this branch's configuration accordingly.
		:param remote_reference: The remote reference to track or None to untrack 
			any references
		:return: self"""
		if remote_reference is not None and not isinstance(remote_reference, RemoteReference):
			raise ValueError("Incorrect parameter type: %r" % remote_reference)
		# END handle type
		
		writer = self.config_writer()
		if remote_reference is None:
			writer.remove_option(self.k_config_remote)
			writer.remove_option(self.k_config_remote_ref)
			if len(writer.options()) == 0:
				writer.remove_section()
			# END handle remove section
		else:
			writer.set_value(self.k_config_remote, remote_reference.remote_name)
			writer.set_value(self.k_config_remote_ref, Head.to_full_path(remote_reference.remote_head))
		# END handle ref value
		
		return self
		
		
	def tracking_branch(self):
		""":return: The remote_reference we are tracking, or None if we are 
			not a tracking branch"""
		reader = self.config_reader()
		if reader.has_option(self.k_config_remote) and reader.has_option(self.k_config_remote_ref):
			ref = Head(self.repo, Head.to_full_path(reader.get_value(self.k_config_remote_ref)))
			remote_refpath = RemoteReference.to_full_path(join_path(reader.get_value(self.k_config_remote), ref.name))
			return RemoteReference(self.repo, remote_refpath)
		# END handle have tracking branch
		
		# we are not a tracking branch
		return None
	
	def rename(self, new_path, force=False):
		"""Rename self to a new path
		
		:param new_path:
			Either a simple name or a path, i.e. new_name or features/new_name.
			The prefix refs/heads is implied
			
		:param force:
			If True, the rename will succeed even if a head with the target name
			already exists.
			
		:return: self
		:note: respects the ref log as git commands are used"""
		flag = "-m"
		if force:
			flag = "-M"
			
		self.repo.git.branch(flag, self, new_path)
		self.path  = "%s/%s" % (self._common_path_default, new_path)
		return self
		
	def checkout(self, force=False, **kwargs):
		"""Checkout this head by setting the HEAD to this reference, by updating the index
		to reflect the tree we point to and by updating the working tree to reflect 
		the latest index.
		
		The command will fail if changed working tree files would be overwritten.
		
		:param force:
			If True, changes to the index and the working tree will be discarded.
			If False, GitCommandError will be raised in that situation.
			
		:param kwargs:
			Additional keyword arguments to be passed to git checkout, i.e.
			b='new_branch' to create a new branch at the given spot.
		
		:return:
			The active branch after the checkout operation, usually self unless
			a new branch has been created.
		
		:note:
			By default it is only allowed to checkout heads - everything else
			will leave the HEAD detached which is allowed and possible, but remains
			a special state that some tools might not be able to handle."""
		args = list()
		kwargs['f'] = force
		if kwargs['f'] == False:
			kwargs.pop('f')
		
		self.repo.git.checkout(self, **kwargs)
		return self.repo.active_branch
		
	#{ Configruation
	
	def _config_parser(self, read_only):
		if read_only:
			parser = self.repo.config_reader()
		else:
			parser = self.repo.config_writer()
		# END handle parser instance
		
		return SectionConstraint(parser, 'branch "%s"' % self.name)
	
	def config_reader(self):
		""":return: A configuration parser instance constrained to only read 
		this instance's values"""
		return self._config_parser(read_only=True)
		
	def config_writer(self):
		""":return: A configuration writer instance with read-and write acccess
			to options of this head"""
		return self._config_parser(read_only=False)
	
	#} END configuration
		

class TagReference(Reference):
	"""Class representing a lightweight tag reference which either points to a commit 
	,a tag object or any other object. In the latter case additional information, 
	like the signature or the tag-creator, is available.
	
	This tag object will always point to a commit object, but may carray additional
	information in a tag object::
	
	 tagref = TagReference.list_items(repo)[0]
	 print tagref.commit.message
	 if tagref.tag is not None:
		print tagref.tag.message"""
	
	__slots__ = tuple()
	_common_path_default = "refs/tags"
	
	@property
	def commit(self):
		""":return: Commit object the tag ref points to"""
		obj = self.object
		if obj.type == "commit":
			return obj
		elif obj.type == "tag":
			# it is a tag object which carries the commit as an object - we can point to anything
			return obj.object
		else:
			raise ValueError( "Tag %s points to a Blob or Tree - have never seen that before" % self )	

	@property
	def tag(self):
		"""
		:return: Tag object this tag ref points to or None in case 
			we are a light weight tag"""
		obj = self.object
		if obj.type == "tag":
			return obj
		return None
		
	# make object read-only
	# It should be reasonably hard to adjust an existing tag
	object = property(Reference._get_object)
		
	@classmethod
	def create(cls, repo, path, ref='HEAD', message=None, force=False, **kwargs):
		"""Create a new tag reference.
		
		:param path:
			The name of the tag, i.e. 1.0 or releases/1.0. 
			The prefix refs/tags is implied
			
		:param ref:
			A reference to the object you want to tag. It can be a commit, tree or 
			blob.
			
		:param message:
			If not None, the message will be used in your tag object. This will also 
			create an additional tag object that allows to obtain that information, i.e.::
			
				tagref.tag.message
			
		:param force:
			If True, to force creation of a tag even though that tag already exists.
			
		:param kwargs:
			Additional keyword arguments to be passed to git-tag
			
		:return: A new TagReference"""
		args = ( path, ref )
		if message:
			kwargs['m'] =  message
		if force:
			kwargs['f'] = True
		
		repo.git.tag(*args, **kwargs)
		return TagReference(repo, "%s/%s" % (cls._common_path_default, path))
		
	@classmethod
	def delete(cls, repo, *tags):
		"""Delete the given existing tag or tags"""
		repo.git.tag("-d", *tags)
		
		
		

		
# provide an alias
Tag = TagReference

class RemoteReference(Head):
	"""Represents a reference pointing to a remote head."""
	_common_path_default = "refs/remotes"
	
	
	@classmethod
	def iter_items(cls, repo, common_path = None, remote=None):
		"""Iterate remote references, and if given, constrain them to the given remote"""
		common_path = common_path or cls._common_path_default
		if remote is not None:
			common_path = join_path(common_path, str(remote))
		# END handle remote constraint
		return super(RemoteReference, cls).iter_items(repo, common_path)
	
	@property
	def remote_name(self):
		"""
		:return:
			Name of the remote we are a reference of, such as 'origin' for a reference
			named 'origin/master'"""
		tokens = self.path.split('/')
		# /refs/remotes/<remote name>/<branch_name>
		return tokens[2]
		
	@property
	def remote_head(self):
		""":return: Name of the remote head itself, i.e. master.
		:note: The returned name is usually not qualified enough to uniquely identify
			a branch"""
		tokens = self.path.split('/')
		return '/'.join(tokens[3:])
		
	@classmethod
	def delete(cls, repo, *refs, **kwargs):
		"""Delete the given remote references.
		:note:
			kwargs are given for compatability with the base class method as we 
			should not narrow the signature."""
		repo.git.branch("-d", "-r", *refs)
		# the official deletion method will ignore remote symbolic refs - these 
		# are generally ignored in the refs/ folder. We don't though 
		# and delete remainders manually
		for ref in refs:
			try:
				os.remove(join(repo.git_dir, ref.path))
			except OSError:
				pass
		# END for each ref
