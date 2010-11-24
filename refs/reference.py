from symbolic import SymbolicReference
import os
from git.objects import Object
from git.util import (
					LazyMixin, 
					Iterable, 
					)

from gitdb.util import (
							isfile,
							hex_to_bin
						)

__all__ = ["Reference"]


class Reference(SymbolicReference, LazyMixin, Iterable):
	"""Represents a named reference to any object. Subclasses may apply restrictions though, 
	i.e. Heads can only point to commits."""
	__slots__ = tuple()
	_points_to_commits_only = False
	_resolve_ref_on_create = True
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

	def set_object(self, object, logmsg = None):
		"""Special version which checks if the head-log needs an update as well"""
		oldbinsha = None
		if logmsg is not None:
			head = self.repo.head
			if not head.is_detached and head.ref == self:
				oldbinsha = self.commit.binsha
			#END handle commit retrieval
		#END handle message is set
		
		super(Reference, self).set_object(object, logmsg)
		
		if oldbinsha is not None:
			# /* from refs.c in git-source
			# * Special hack: If a branch is updated directly and HEAD
			# * points to it (may happen on the remote side of a push
			# * for example) then logically the HEAD reflog should be
			# * updated too.
			# * A generic solution implies reverse symref information,
			# * but finding all symrefs pointing to the given branch
			# * would be rather costly for this rare event (the direct
			# * update of a branch) to be worth it.  So let's cheat and
			# * check with HEAD only which should cover 99% of all usage
			# * scenarios (even 100% of the default ones).
			# */
			self.repo.head.log_append(oldbinsha, logmsg)
		#END check if the head

	# NOTE: Don't have to overwrite properties as the will only work without a the log

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
	def iter_items(cls, repo, common_path = None):
		"""Equivalent to SymbolicReference.iter_items, but will return non-detached
		references as well."""
		return cls._iter_items(repo, common_path)
