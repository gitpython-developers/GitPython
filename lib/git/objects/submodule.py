import base
from cStringIO import StringIO
from git.config import GitConfigParser
from git.util import join_path_native
from git.exc import InvalidGitRepositoryError, NoSuchPathError

__all__ = ("Submodule", )

class SubmoduleConfigParser(GitConfigParser):
	"""Catches calls to _write, and updates the .gitmodules blob in the index
	with the new data, if we have written into a stream. Otherwise it will 
	add the local file to the index to make it correspond with the working tree."""
	_mutating_methods_ = tuple()
	

class Submodule(base.IndexObject):
	"""Implements access to a git submodule. They are special in that their sha
	represents a commit in the submodule's repository which is to be checked out
	at the path of this instance. 
	The submodule type does not have a string type associated with it, as it exists
	solely as a marker in the tree and index.
	
	All methods work in bare and non-bare repositories."""
	
	kModulesFile = '.gitmodules'
	
	# this is a bogus type for base class compatability
	type = 'submodule'
	
	__slots__ = ('_parent_commit', '_url', '_ref')
	
	def _set_cache_(self, attr):
		if attr == 'size':
			raise ValueError("Submodules do not have a size as they do not refer to anything in this repository")
		elif attr == '_parent_commit':
			# set a default value, which is the root tree of the current head
			self._parent_commit = self.repo.commit()
		elif attr in ('path', '_url', '_ref'):
			reader = self.config_reader()
			# default submodule values
			self._path = reader.get_value('path')
			self._url = reader.get_value('url')
			# git-python extension values - optional
			self._ref = reader.get_value('ref', 'master')
		else:
			super(Submodule, self)._set_cache_(attr)
		# END handle attribute name
	
	def _sio_modules(self):
		""":return: Configuration file as StringIO - we only access it through the respective blob's data"""
		sio = StringIO(self._parent_commit.tree[self.kModulesFile].datastream.read())
		sio.name = self.kModulesFile
		return sio
		
	def _config_parser(self, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode"""
		parent_matches_head = self.repo.head.commit == self._parent_commit
		if not self.repo.bare and parent_matches_head:
			fp_module = self.kModulesFile
		else:
			fp_module = self._sio_modules()
		# END handle non-bare working tree
		
		if not read_only and not parent_matches_head:
			raise ValueError("Cannot write blobs of 'historical' submodule configurations")
		# END handle writes of historical submodules
		
		parser = GitConfigParser(fp_module, read_only = read_only)
		return SectionConstraint(parser, 'submodule "%s"' % self.path)
		
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
		
	def set_parent_commit(self, commit):
		"""Set this instance to use the given commit whose tree is supposed to 
		contain the .gitmodules blob.
		:param commit: Commit'ish reference pointing at the root_tree
		:raise ValueError: if the commit's tree didn't contain the .gitmodules blob."""
		pcommit = self.repo.commit(commit)
		if self.kModulesFile not in pcommit.tree:
			raise ValueError("Tree of commit %s did not contain the %s file" % (commit, self.kModulesFile))
		# END handle exceptions
		self._parent_commit = pcommit
		
		# clear the possibly changed values
		for name in ('path', '_ref', '_url'):
			try:
				delattr(self, name)
			except AttributeError:
				pass
		# END for each name to delete
		
	def config_writer(self):
		""":return: a config writer instance allowing you to read and write the data
		belonging to this submodule into the .gitmodules file."""
		return self._config_parser(read_only=False)
		
	#} END edit interface
	
	#{ Query Interface
	
	def module(self):
		""":return: Repo instance initialized from the repository at our submodule path
		:raise InvalidGitRepositoryError: if a repository was not available"""
		if self.repo.bare:
			raise InvalidGitRepositoryError("Cannot retrieve module repository in bare parent repositories")
		# END handle bare mode
		
		repo_path = join_path_native(self.repo.working_tree_dir, self.path)
		try:
			return Repo(repo_path)
		except (InvalidGitRepositoryError, NoSuchPathError):
			raise InvalidGitRepositoryError("No valid repository at %s" % self.path)
		# END handle exceptions
		
	def ref(self):
		""":return: The reference's name that we are to checkout"""
		return self._ref
		
	def url(self):
		""":return: The url to the repository which our module-repository refers to"""
		return self._url
	
	def parent_commit(self):
		""":return: Commit instance with the tree containing the .gitmodules file
		:note: will always point to the current head's commit if it was not set explicitly"""
		return self._parent_commit
	
	def config_reader(self):
		""":return: ConfigReader instance which allows you to qurey the configuration values
		of this submodule, as provided by the .gitmodules file
		:note: The config reader will actually read the data directly from the repository
			and thus does not need nor care about your working tree.
		:note: Should be cached by the caller and only kept as long as needed"""
		return self._config_parser.read_only(read_only=True)
		
	#} END query interface
