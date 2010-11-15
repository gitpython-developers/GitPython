import base
from StringIO import StringIO					# need a dict to set bloody .name field
from git.util import Iterable
from git.config import GitConfigParser, SectionConstraint
from git.util import join_path_native
from git.exc import InvalidGitRepositoryError, NoSuchPathError

import os

__all__ = ("Submodule", )

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
	"""Catches calls to _write, and updates the .gitmodules blob in the index
	with the new data, if we have written into a stream. Otherwise it will 
	add the local file to the index to make it correspond with the working tree."""
	_mutating_methods_ = tuple()
	

class Submodule(base.IndexObject, Iterable):
	"""Implements access to a git submodule. They are special in that their sha
	represents a commit in the submodule's repository which is to be checked out
	at the path of this instance. 
	The submodule type does not have a string type associated with it, as it exists
	solely as a marker in the tree and index.
	
	All methods work in bare and non-bare repositories."""
	
	_id_attribute_ = "path"
	k_modules_file = '.gitmodules'
	k_ref_option = 'ref'
	k_ref_default = 'master'
	
	# this is a bogus type for base class compatability
	type = 'submodule'
	
	__slots__ = ('_parent_commit', '_url', '_ref', '_name')
	
	def __init__(self, repo, binsha, mode=None, path=None, name = None, parent_commit=None, url=None, ref=None):
		"""Initialize this instance with its attributes. We only document the ones 
		that differ from ``IndexObject``
		:param binsha: binary sha referring to a commit in the remote repository, see url parameter
		:param parent_commit: see set_parent_commit()
		:param url: The url to the remote repository which is the submodule
		:param ref: Reference to checkout when cloning the remote repository"""
		super(Submodule, self).__init__(repo, binsha, mode, path)
		if parent_commit is not None:
			self._parent_commit = parent_commit
		if url is not None:
			self._url = url
		if ref is not None:
			self._ref = ref
		if name is not None:
			self._name = name
	
	def _set_cache_(self, attr):
		if attr == 'size':
			raise ValueError("Submodules do not have a size as they do not refer to anything in this repository")
		elif attr == '_parent_commit':
			# set a default value, which is the root tree of the current head
			self._parent_commit = self.repo.commit()
		elif attr in ('path', '_url', '_ref'):
			reader = self.config_reader()
			# default submodule values
			self.path = reader.get_value('path')
			self._url = reader.get_value('url')
			# git-python extension values - optional
			self._ref = reader.get_value(self.k_ref_option, self.k_ref_default)
		elif attr == '_name':
			raise AttributeError("Cannot retrieve the name of a submodule if it was not set initially")
		else:
			super(Submodule, self)._set_cache_(attr)
		# END handle attribute name
		
	def __eq__(self, other):
		"""Compare with another submodule"""
		return self.path == other.path and self.url == other.url and super(Submodule, self).__eq__(other)
		
	def __ne__(self, other):
		"""Compare with another submodule for inequality"""
		return not (self == other)
		
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
		else:
			try:
				fp_module = cls._sio_modules(parent_commit)
			except KeyError:
				raise IOError("Could not find %s file in the tree of parent commit %s" % (cls.k_modules_file, parent_commit))
			# END handle exceptions
		# END handle non-bare working tree
		
		if not read_only and not parent_matches_head:
			raise ValueError("Cannot write blobs of 'historical' submodule configurations")
		# END handle writes of historical submodules
		
		return GitConfigParser(fp_module, read_only = read_only)

		
	@classmethod
	def _sio_modules(cls, parent_commit):
		""":return: Configuration file as StringIO - we only access it through the respective blob's data"""
		sio = StringIO(parent_commit.tree[cls.k_modules_file].data_stream.read())
		sio.name = cls.k_modules_file
		return sio
	
	def _config_parser_constrained(self, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode"""
		parser = self._config_parser(self.repo, self._parent_commit, read_only)
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
		
	def set_parent_commit(self, commit, check=True):
		"""Set this instance to use the given commit whose tree is supposed to 
		contain the .gitmodules blob.
		:param commit: Commit'ish reference pointing at the root_tree
		:param check: if True, relatively expensive checks will be performed to verify
			validity of the submodule.
		:raise ValueError: if the commit's tree didn't contain the .gitmodules blob.
		:raise ValueError: if the parent commit didn't store this submodule under the
			current path"""
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
		
		# clear the possibly changed values
		for name in ('path', '_ref', '_url'):
			try:
				delattr(self, name)
			except AttributeError:
				pass
			# END try attr deletion
		# END for each name to delete
		
	def config_writer(self):
		""":return: a config writer instance allowing you to read and write the data
		belonging to this submodule into the .gitmodules file.
		
		:raise ValueError: if trying to get a writer on a parent_commit which does not
			match the current head commit
		:raise IOError: If the .gitmodules file/blob could not be read"""
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
		
		repo_path = join_path_native(self.repo.working_tree_dir, self.path)
		try:
			repo = Repo(repo_path)
			if repo != self.repo:
				return repo
			# END handle repo uninitialized
		except (InvalidGitRepositoryError, NoSuchPathError):
			raise InvalidGitRepositoryError("No valid repository at %s" % self.path)
		else:
			raise InvalidGitRepositoryError("Repository at %r was not yet checked out" % repo_path)
		# END handle exceptions
	
	@property
	def ref(self):
		""":return: The reference's name that we are to checkout"""
		return self._ref
	
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
			r = cls.k_ref_default
			if parser.has_option(sms, cls.k_ref_option):
				r = parser.get_value(sms, cls.k_ref_option)
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
			sm._ref = r
			sm._url = u
			
			yield sm
		# END for each section
	
	#} END iterable interface
	
#} END classes
