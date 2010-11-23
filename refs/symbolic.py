import os
from git.objects import Commit
from git.util import (
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
							hex_to_bin,
							LockedFD
						)

from log import RefLog

__all__ = ["SymbolicReference"]

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
		
	def _set_reference(self, ref, msg = None):
		"""Set ourselves to the given ref. It will stay a symbol if the ref is a Reference.
		Otherwise we try to get a commit from it using our interface.
		
		Strings are allowed but will be checked to be sure we have a commit
		:param msg: If set to a string, the message will be used in the reflog.
			Otherwise, a reflog entry is not written for the changed reference"""
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
		
		# TODO: Write using LockedFD
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
	
	def log(self):
		"""
		:return: RefLog for this reference. Its last entry reflects the latest change
			applied to this reference
			
		.. note:: As the log is parsed every time, its recommended to cache it for use
			instead of calling this method repeatedly. It should be considered read-only."""
		return RefLog.from_file(RefLog.path(self))
		
	def log_append(self, oldbinsha, message, newbinsha=None):
		"""Append a logentry to the logfile of this ref
		:param oldbinsha: binary sha this ref used to point to
		:param message: A message describing the change
		:param newbinsha: The sha the ref points to now. If None, our current commit sha
			will be used
		:return: added RefLogEntry instance"""
		return RefLog.append_entry(RefLog.path(self), oldbinsha, 
									(newbinsha is None and self.commit.binsha) or newbinsha, 
									message) 

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
