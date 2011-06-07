
from symbolic import SymbolicReference
from git.exc import GitCommandError

__all__ = ["HEAD"]

	
class HEAD(SymbolicReference):
	"""Provides additional functionality using the git command"""
	__slots__ = tuple()
	
	_HEAD_NAME = 'HEAD'
	_ORIG_HEAD_NAME = 'ORIG_HEAD'
	__slots__ = tuple()
	
	def __init__(self, repo, path=_HEAD_NAME):
		if path != self._HEAD_NAME:
			raise ValueError("HEAD instance must point to %r, got %r" % (self._HEAD_NAME, path))
		super(HEAD, self).__init__(repo, path)
	
	def orig_head(self):
		"""
		:return: SymbolicReference pointing at the ORIG_HEAD, which is maintained 
			to contain the previous value of HEAD"""
		return SymbolicReference(self.repo, self._ORIG_HEAD_NAME)
		
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
	
