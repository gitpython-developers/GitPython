# remote.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module implementing a remote object allowing easy access to git remotes
"""

from git.utils import LazyMixin, Iterable
from refs import RemoteRef

class _SectionConstrain(object):
	"""
	Constrains a ConfigParser to only option commands which are constrained to 
	always use the section we have been initialized with
	"""
	__slots__ = ( "_config", "_section_name"
	_valid_attrs_ = ("get", "set", "getint", "getfloat", "getboolean")
	
	def __init__(self, config, section):
		self._config = config
		self._section_name = section
		
	def __getattr__(self, attr):
		
		
	def get(option):
		return self._config.get(self._section_name, option)
		
	def set(option, value):
		return self._config.set(self._section_name, option, value)
		
	

class Remote(LazyMixin, Iterable):
	"""
	Provides easy read and write access to a git remote.
	
	Everything not part of this interface is considered an option for the current 
	remote, allowing constructs like remote.pushurl to query the pushurl.
	
	NOTE: When querying configuration, the configuration accessor will be cached
	to speed up subsequent accesses.
	"""
	
	__slots__ = ( "repo", "name", "_config" )
	
	def __init__(self, repo, name):
		"""
		Initialize a remote instance
		
		``repo``
			The repository we are a remote of
			
		``name``
			the name of the remote, i.e. 'origin'
		"""
		self.repo = repo
		self.name = name
		
	def __getattr__(self, attr):
		"""
		Allows to call this instance like 
		remote.special( *args, **kwargs) to call git-remote special self.name
		"""
		return self._call_cmd(attr)
	
	def _set_cache_(self, attr):
		if attr == "_config":
			self._config = self.repo.config_reader
		else:
			super(Remote, self)._set_cache_(attr)
			
	
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
	
	@classmethod
	def iter_items(cls, repo):
		"""
		Returns
			Iterator yielding Remote objects of the given repository
		"""
		# parse them using refs, as their query can be faster as it is 
		# purely based on the file system
		seen_remotes = set()
		for ref in RemoteRef.iter_items(repo):
			remote_name = ref.remote_name
			if remote_name in seen_remotes:
				continue
			# END if remote done already
			seen_remotes.add(remote_name)
			yield Remote(repo, remote_name)
		# END for each ref
		
	@property
	def refs(self):
		"""
		Returns
			List of RemoteRef objects
		"""
		out_refs = list()
		for ref in RemoteRef.list_items(self.repo):
			if ref.remote_name == self.name:
				out_refs.append(ref)
			# END if names match
		# END for each ref
		assert out_refs, "Remote %s did not have any references" % self.name
		return out_refs
	
	@classmethod
	def create(cls, repo, name, url, **kwargs):
		"""
		Create a new remote to the given repository
		``repo``
			Repository instance that is to receive the new remote
		
		``name``
			Desired name of the remote
		
		``url``
			URL which corresponds to the remote's name
			
		``**kwargs``
			Additional arguments to be passed to the git-remote add command
			
		Returns
			New Remote instance
			
		Raise
			GitCommandError in case an origin with that name already exists
		"""
		self.repo.git.remote( "add", name, url, **kwargs )
		return cls(repo, name)
	
	# add is an alias
	add = create
	
	@classmethod
	def remove(cls, repo, name ):
		"""
		Remove the remote with the given name
		"""
		repo.git.remote("rm", name)
		
	def rename(self, new_name):
		"""
		Rename self to the given new_name
		
		Returns
			self
		"""
		if self.name == new_name:
			return self
		
		self.repo.git.remote("rename", self.name, new_name)
		self.name = new_name
		del(self._config)		# it contains cached values, section names are different now
		return self
		
	def update(self, **kwargs):
		"""
		Fetch all changes for this remote, including new branches
		
		``kwargs``
			Additional arguments passed to git-remote update
		
		Returns
			self
		"""
		self.repo.git.remote("update", self.name)
		return self
	
