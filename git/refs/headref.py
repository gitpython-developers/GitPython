from reference import Reference
from git.config import SectionConstraint
from git.util import join_path

__all__ = ["Head"]

class Head(Reference):
	"""The GitPyhton Head implementation provides more git-command based features
	
	A Head is a named reference to a Commit. Every Head instance contains a name
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
	__slots__ = tuple()
	
	_common_path_default = "refs/heads"
	k_config_remote = "remote"
	k_config_remote_ref = "merge"			# branch to merge from remote
	
	# will be set by init method !
	RemoteReferenceCls = None
	
	#{ Configuration
	
	def set_tracking_branch(self, remote_reference):
		"""
		Configure this branch to track the given remote reference. This will alter
			this branch's configuration accordingly.
		
		:param remote_reference: The remote reference to track or None to untrack 
			any references
		:return: self"""
		if remote_reference is not None and not isinstance(remote_reference, self.RemoteReferenceCls):
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
		"""
		:return: The remote_reference we are tracking, or None if we are 
			not a tracking branch"""
		reader = self.config_reader()
		if reader.has_option(self.k_config_remote) and reader.has_option(self.k_config_remote_ref):
			ref = Head(self.repo, Head.to_full_path(reader.get_value(self.k_config_remote_ref)))
			remote_refpath = self.RemoteReferenceCls.to_full_path(join_path(reader.get_value(self.k_config_remote), ref.name))
			return self.RemoteReferenceCls(self.repo, remote_refpath)
		# END handle have tracking branch
		
		# we are not a tracking branch
		return None
	
		
	#{ Configruation
	
	def _config_parser(self, read_only):
		if read_only:
			parser = self.repo.config_reader()
		else:
			parser = self.repo.config_writer()
		# END handle parser instance
		
		return SectionConstraint(parser, 'branch "%s"' % self.name)
	
	def config_reader(self):
		"""
		:return: A configuration parser instance constrained to only read 
			this instance's values"""
		return self._config_parser(read_only=True)
		
	def config_writer(self):
		"""
		:return: A configuration writer instance with read-and write acccess
			to options of this head"""
		return self._config_parser(read_only=False)
	
	#} END configuration
	
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

		

