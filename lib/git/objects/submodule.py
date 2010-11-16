import base
from util import Traversable
from StringIO import StringIO					# need a dict to set bloody .name field
from git.util import Iterable
from git.config import GitConfigParser, SectionConstraint
from git.util import join_path_native
from git.exc import InvalidGitRepositoryError, NoSuchPathError
import stat

import os
import sys
import weakref

__all__ = ("Submodule", "RootModule")

#{ Utilities

def sm_section(path):
	""":return: section title used in .gitmodules configuration file"""
	return 'submodule "%s"' % path

def sm_name(section):
	""":return: name of the submodule as parsed from the section name"""
	section = section.strip()
	return section[11:-1]
#} END utilities


#{ Classes

class SubmoduleConfigParser(GitConfigParser):
	"""
	Catches calls to _write, and updates the .gitmodules blob in the index
	with the new data, if we have written into a stream. Otherwise it will 
	add the local file to the index to make it correspond with the working tree.
	Additionally, the cache must be cleared
	"""
	
	def __init__(self, *args, **kwargs):
		self._smref = None
		super(SubmoduleConfigParser, self).__init__(*args, **kwargs)
	
	#{ Interface
	def set_submodule(self, submodule):
		"""Set this instance's submodule. It must be called before 
		the first write operation begins"""
		self._smref = weakref.ref(submodule)

	def flush_to_index(self):
		"""Flush changes in our configuration file to the index"""
		assert self._smref is not None
		# should always have a file here
		assert not isinstance(self._file_or_files, StringIO)
		
		sm = self._smref()
		if sm is not None:
			sm.repo.index.add([sm.k_modules_file])
			sm._clear_cache()
		# END handle weakref

	#} END interface
	
	#{ Overridden Methods
	def write(self):
		rval = super(SubmoduleConfigParser, self).write()
		self.flush_to_index()
		return rval
	# END overridden methods

class Submodule(base.IndexObject, Iterable, Traversable):
	"""Implements access to a git submodule. They are special in that their sha
	represents a commit in the submodule's repository which is to be checked out
	at the path of this instance. 
	The submodule type does not have a string type associated with it, as it exists
	solely as a marker in the tree and index.
	
	All methods work in bare and non-bare repositories."""
	
	_id_attribute_ = "name"
	k_modules_file = '.gitmodules'
	k_head_option = 'branch'
	k_head_default = 'master'
	k_def_mode = stat.S_IFDIR | stat.S_IFLNK		# submodules are directories with link-status
	
	# this is a bogus type for base class compatability
	type = 'submodule'
	
	__slots__ = ('_parent_commit', '_url', '_branch', '_name', '__weakref__')
	
	def __init__(self, repo, binsha, mode=None, path=None, name = None, parent_commit=None, url=None, branch=None):
		"""Initialize this instance with its attributes. We only document the ones 
		that differ from ``IndexObject``
		:param repo: Our parent repository
		:param binsha: binary sha referring to a commit in the remote repository, see url parameter
		:param parent_commit: see set_parent_commit()
		:param url: The url to the remote repository which is the submodule
		:param ref: Reference to checkout when cloning the remote repository"""
		super(Submodule, self).__init__(repo, binsha, mode, path)
		if parent_commit is not None:
			self._parent_commit = parent_commit
		if url is not None:
			self._url = url
		if branch is not None:
			self._branch = branch
		if name is not None:
			self._name = name
	
	def _set_cache_(self, attr):
		if attr == 'size':
			raise ValueError("Submodules do not have a size as they do not refer to anything in this repository")
		elif attr == '_parent_commit':
			# set a default value, which is the root tree of the current head
			self._parent_commit = self.repo.commit()
		elif attr in ('path', '_url', '_branch'):
			reader = self.config_reader()
			# default submodule values
			self.path = reader.get_value('path')
			self._url = reader.get_value('url')
			# git-python extension values - optional
			self._branch = reader.get_value(self.k_head_option, self.k_head_default)
		elif attr == '_name':
			raise AttributeError("Cannot retrieve the name of a submodule if it was not set initially")
		else:
			super(Submodule, self)._set_cache_(attr)
		# END handle attribute name
		
	def _get_intermediate_items(self, item):
		""":return: all the submodules of our module repository"""
		try:
			return type(self).list_items(item.module())
		except InvalidGitRepositoryError:
			return list()
		# END handle intermeditate items
		
	def __eq__(self, other):
		"""Compare with another submodule"""
		return self.path == other.path and self.url == other.url and super(Submodule, self).__eq__(other)
		
	def __ne__(self, other):
		"""Compare with another submodule for inequality"""
		return not (self == other)
		
	def __hash__(self):
		"""Hash this instance using its logical id, not the sha"""
		return hash(self._name)
		
	@classmethod
	def _config_parser(cls, repo, parent_commit, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode
		:raise IOError: If the .gitmodules file cannot be found, either locally or in the repository
			at the given parent commit. Otherwise the exception would be delayed until the first 
			access of the config parser"""
		parent_matches_head = repo.head.commit == parent_commit
		if not repo.bare and parent_matches_head:
			fp_module = cls.k_modules_file
			fp_module_path = os.path.join(repo.working_tree_dir, fp_module)
			if not os.path.isfile(fp_module_path):
				raise IOError("%s file was not accessible" % fp_module_path)
			# END handle existance
			fp_module = fp_module_path
		else:
			try:
				fp_module = cls._sio_modules(parent_commit)
			except KeyError:
				raise IOError("Could not find %s file in the tree of parent commit %s" % (cls.k_modules_file, parent_commit))
			# END handle exceptions
		# END handle non-bare working tree
		
		if not read_only and (repo.bare or not parent_matches_head):
			raise ValueError("Cannot write blobs of 'historical' submodule configurations")
		# END handle writes of historical submodules
		
		return SubmoduleConfigParser(fp_module, read_only = read_only)

	def _clear_cache(self):
		# clear the possibly changed values
		for name in ('path', '_branch', '_url'):
			try:
				delattr(self, name)
			except AttributeError:
				pass
			# END try attr deletion
		# END for each name to delete
		
	@classmethod
	def _sio_modules(cls, parent_commit):
		""":return: Configuration file as StringIO - we only access it through the respective blob's data"""
		sio = StringIO(parent_commit.tree[cls.k_modules_file].data_stream.read())
		sio.name = cls.k_modules_file
		return sio
	
	def _config_parser_constrained(self, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode"""
		parser = self._config_parser(self.repo, self._parent_commit, read_only)
		parser.set_submodule(self)
		return SectionConstraint(parser, sm_section(self.name))
		
	#{ Edit Interface
	
	@classmethod
	def add(cls, repo, path, url, skip_init=False):
		"""Add a new submodule to the given repository. This will alter the index
		as well as the .gitmodules file, but will not create a new commit.
		:param repo: Repository instance which should receive the submodule
		:param path: repository-relative path at which the submodule should be located
			It will be created as required during the repository initialization.
		:param url: git-clone compatible URL, see git-clone reference for more information
		:param skip_init: if True, the new repository will not be cloned to its location.
		:return: The newly created submodule instance"""
		
	def update(self, recursive=False, init=True):
		"""Update the repository of this submodule to point to the checkout
		we point at with the binsha of this instance.
		:param recursive: if True, we will operate recursively and update child-
			modules as well.
		:param init: if True, the module repository will be cloned into place if necessary
		:note: does nothing in bare repositories
		:return: self"""
		if self.repo.bare:
			return self
		#END pass in bare mode
		
		try:
			mrepo = self.module()
			for remote in mrepo.remotes:
				remote.fetch()
			#END fetch new data
		except InvalidGitRepositoryError:
			if not init:
				return self
			# END early abort if init is not allowed
			import git
			
			# there is no git-repository yet - but delete empty paths
			module_path = join_path_native(self.repo.working_tree_dir, self.path)
			if os.path.isdir(module_path):
				try:
					os.rmdir(module_path)
				except OSError:
					raise OSError("Module directory at %r does already exist and is non-empty" % module_path)
				# END handle OSError
			# END handle directory removal
			
			# don't check it out at first - nonetheless it will create a local
			# branch according to the remote-HEAD if possible
			mrepo = git.Repo.clone_from(self.url, module_path, n=True)
			
			# see whether we have a valid branch to checkout
			try:
				remote_branch = mrepo.remotes.origin.refs[self.branch]
				local_branch = git.Head(mrepo, git.Head.to_full_path(self.branch))
				if not local_branch.is_valid():
					mrepo.git.checkout(remote_branch, b=self.branch)
				else:
					# have a valid branch, but no checkout - make sure we can figure
					# that out by marking the commit with a null_sha
					# have to write it directly as .commit = NULLSHA tries to resolve the sha
					ref = mrepo.head.ref
					refpath = join_path_native(mrepo.git_dir, ref.to_full_path(ref.path))
					refdir = os.path.dirname(refpath)
					if not os.path.isdir(refdir):
						os.makedirs(refdir)
					#END handle directory
					open(refpath, 'w').write(self.NULL_HEX_SHA)
				# END initial checkout + branch creation
				# make sure we are not detached
				mrepo.head.ref = local_branch
			except IndexError:
				print >> sys.stderr, "Warning: Failed to checkout tracking branch %s" % self.branch 
			#END handle tracking branch
		#END handle initalization
		
		# update the working tree
		if mrepo.head.commit.binsha != self.binsha:
			if mrepo.head.is_detached:
				mrepo.git.checkout(self.hexsha)
			else:
				# TODO: allow to specify a rebase, merge, or reset
				# TODO: Warn if the hexsha forces the tracking branch off the remote
				# branch - this should be prevented when setting the branch option
				mrepo.head.reset(self.hexsha, index=True, working_tree=True)
			# END handle checkout
			
			if recursive:
				for submodule in self.iter_items(self.module()):
					submodule.update(recursive, init)
				# END handle recursive update
			# END for each submodule
		# END update to new commit only if needed
			
		return self
		
	def set_parent_commit(self, commit, check=True):
		"""Set this instance to use the given commit whose tree is supposed to 
		contain the .gitmodules blob.
		:param commit: Commit'ish reference pointing at the root_tree
		:param check: if True, relatively expensive checks will be performed to verify
			validity of the submodule.
		:raise ValueError: if the commit's tree didn't contain the .gitmodules blob.
		:raise ValueError: if the parent commit didn't store this submodule under the
			current path
		:return: self"""
		pcommit = self.repo.commit(commit)
		pctree = pcommit.tree
		if self.k_modules_file not in pctree:
			raise ValueError("Tree of commit %s did not contain the %s file" % (commit, self.k_modules_file))
		# END handle exceptions
		
		prev_pc = self._parent_commit
		self._parent_commit = pcommit
		
		if check:
			parser = self._config_parser(self.repo, self._parent_commit, read_only=True)
			if not parser.has_section(sm_section(self.name)):
				self._parent_commit = prev_pc
				raise ValueError("Submodule at path %r did not exist in parent commit %s" % (self.path, commit)) 
			# END handle submodule did not exist
		# END handle checking mode
		
		# update our sha, it could have changed
		self.binsha = pctree[self.path].binsha
		
		self._clear_cache()
		
		return self
		
	def config_writer(self):
		""":return: a config writer instance allowing you to read and write the data
		belonging to this submodule into the .gitmodules file.
		
		:raise ValueError: if trying to get a writer on a parent_commit which does not
			match the current head commit
		:raise IOError: If the .gitmodules file/blob could not be read"""
		if self.repo.bare:
			raise InvalidGitRepositoryError("Cannot change submodule configuration in a bare repository")
		return self._config_parser_constrained(read_only=False)
		
	#} END edit interface
	
	#{ Query Interface
	
	def module(self):
		""":return: Repo instance initialized from the repository at our submodule path
		:raise InvalidGitRepositoryError: if a repository was not available. This could 
			also mean that it was not yet initialized"""
		# late import to workaround circular dependencies
		from git.repo import Repo
		
		if self.repo.bare:
			raise InvalidGitRepositoryError("Cannot retrieve module repository in bare parent repositories")
		# END handle bare mode
		
		module_path = self.module_path() 
		try:
			repo = Repo(module_path)
			if repo != self.repo:
				return repo
			# END handle repo uninitialized
		except (InvalidGitRepositoryError, NoSuchPathError):
			raise InvalidGitRepositoryError("No valid repository at %s" % self.path)
		else:
			raise InvalidGitRepositoryError("Repository at %r was not yet checked out" % module_path)
		# END handle exceptions
		
	def module_path(self):
		""":return: full path to the root of our module. It is relative to the filesystem root"""
		return join_path_native(self.repo.working_tree_dir, self.path)
		
	def module_exists(self):
		""":return: True if our module exists and is a valid git repository. See module() method"""
		try:
			self.module()
			return True
		except InvalidGitRepositoryError:
			return False
		# END handle exception
	
	@property
	def branch(self):
		""":return: The branch name that we are to checkout"""
		return self._branch
	
	@property
	def url(self):
		""":return: The url to the repository which our module-repository refers to"""
		return self._url
	
	@property
	def parent_commit(self):
		""":return: Commit instance with the tree containing the .gitmodules file
		:note: will always point to the current head's commit if it was not set explicitly"""
		return self._parent_commit
		
	@property
	def name(self):
		""":return: The name of this submodule. It is used to identify it within the 
			.gitmodules file.
		:note: by default, the name is the path at which to find the submodule, but
			in git-python it should be a unique identifier similar to the identifiers
			used for remotes, which allows to change the path of the submodule
			easily
		"""
		return self._name
	
	def config_reader(self):
		""":return: ConfigReader instance which allows you to qurey the configuration values
		of this submodule, as provided by the .gitmodules file
		:note: The config reader will actually read the data directly from the repository
			and thus does not need nor care about your working tree.
		:note: Should be cached by the caller and only kept as long as needed
		:raise IOError: If the .gitmodules file/blob could not be read"""
		return self._config_parser_constrained(read_only=True)
		
	def children(self):
		""":return: IterableList(Submodule, ...) an iterable list of submodules instances
		which are children of this submodule
		:raise InvalidGitRepositoryError: if the submodule is not checked-out"""
		return self._get_intermediate_items(self)
		
	#} END query interface
	
	#{ Iterable Interface
	
	@classmethod
	def iter_items(cls, repo, parent_commit='HEAD'):
		""":return: iterator yielding Submodule instances available in the given repository"""
		pc = repo.commit(parent_commit)			# parent commit instance
		try:
			parser = cls._config_parser(repo, pc, read_only=True)
		except IOError:
			raise StopIteration
		# END handle empty iterator
		
		rt = pc.tree								# root tree
		
		for sms in parser.sections():
			n = sm_name(sms)
			p = parser.get_value(sms, 'path')
			u = parser.get_value(sms, 'url')
			b = cls.k_head_default
			if parser.has_option(sms, cls.k_head_option):
				b = parser.get_value(sms, cls.k_head_option)
			# END handle optional information
			
			# get the binsha
			try:
				sm = rt[p]
			except KeyError:
				raise InvalidGitRepositoryError("Gitmodule path %r did not exist in revision of parent commit %s" % (p, parent_commit))
			# END handle critical error
			
			# fill in remaining info - saves time as it doesn't have to be parsed again
			sm._name = n
			sm._parent_commit = pc
			sm._branch = b
			sm._url = u
			
			yield sm
		# END for each section
	
	#} END iterable interface
	
	
class RootModule(Submodule):
	"""A (virtual) Root of all submodules in the given repository. It can be used
	to more easily traverse all submodules of the master repository"""
	
	__slots__ = tuple()
	
	k_root_name = '__ROOT__'
	
	def __init__(self, repo):
		# repo, binsha, mode=None, path=None, name = None, parent_commit=None, url=None, ref=None)
		super(RootModule, self).__init__(
										repo, 
										binsha = self.NULL_BIN_SHA, 
										mode = self.k_def_mode, 
										path = '', 
										name = self.k_root_name, 
										parent_commit = repo.head.commit,
										url = '',
										branch = self.k_head_default
										)
		
	
	def _clear_cache(self):
		"""May not do anything"""
		pass
	
	#{ Interface 
	def module(self):
		""":return: the actual repository containing the submodules"""
		return self.repo
	#} END interface
#} END classes
