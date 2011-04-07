
from gitdb.ref.head import HEAD as GitDB_HEAD
from gitdb.ref.head import Head as GitDB_Head
from git.exc import GitCommandError
from git.util import RepoAliasMixin

__all__ = ["HEAD", "Head"]

	
class HEAD(GitDB_HEAD, RepoAliasMixin):
	"""Provides additional functionality using the git command"""
	__slots__ = tuple()
		
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
	

class Head(GitDB_Head, RepoAliasMixin):
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

