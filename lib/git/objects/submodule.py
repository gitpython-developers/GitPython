import base
from cStringIO import StringIO
from git.config import GitConfigParser
from git.util import join_path_native
from git.exc import InvalidGitRepositoryError, NoSuchPathError

__all__ = ("Submodule", )

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
	
	__slots__ = ('_root_tree', '_url', '_ref')
	
	def _set_cache_(self, attr):
		if attr == 'size':
			raise ValueError("Submodules do not have a size as they do not refer to anything in this repository")
		elif attr == '_root_tree':
			# set a default value, which is the root tree of the current head
			self._root_tree = self.repo.tree()
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
	
	def _fp_config(self):
		""":return: Configuration file as StringIO - we only access it through the respective blob's data"""
		return StringIO(self._root_tree[self.kModulesFile].datastream.read())
		
	def _config_parser(self, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode"""
		parser = GitConfigParser(self._fp_config(), read_only = read_only)
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
		
	def set_root_tree(self, root_tree):
		"""Set this instance to use the given tree which is supposed to contain the 
		.gitmodules blob.
		:param root_tree: Tree'ish reference pointing at the root_tree
		:raise ValueError: if the root_tree didn't contain the .gitmodules blob."""
		tree = self.repo.tree(root_tree)
		if self.kModulesFile not in tree:
			raise ValueError("Tree %s did not contain the %s file" % (root_tree, self.kModulesFile))
		# END handle exceptions
		self._root_tree = tree
		
		# clear the possibly changing values
		del(self.path)
		del(self._ref)
		del(self._url)
		
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
	
	def root_tree(self):
		""":return: Tree instance referring to the tree which contains the .gitmodules file
		we are to use
		:note: will always point to the current head's root tree if it was not set explicitly"""
		return self._root_tree
	
	def config_reader(self):
		""":return: ConfigReader instance which allows you to qurey the configuration values
		of this submodule, as provided by the .gitmodules file
		:note: The config reader will actually read the data directly from the repository
			and thus does not need nor care about your working tree.
		:note: Should be cached by the caller and only kept as long as needed"""
		return self._config_parser.read_only(read_only=True)
		
	#} END query interface
