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

	def _get_object(self):
		"""
		:return:
			The object our ref currently refers to. Refs can be cached, they will 
			always point to the actual object as it gets re-created on each query"""
		# have to be dynamic here as we may be a tag which can point to anything
		# Our path will be resolved to the hexsha which will be used accordingly
		return Object.new_from_sha(self.repo, hex_to_bin(self.dereference_recursive(self.repo, self.path)))
		
	def _set_object(self, ref):
		"""
		Set our reference to point to the given ref. It will be converted
		to a specific hexsha.
		If the reference does not exist, it will be created.
		
		:note: 
			TypeChecking is done by the git command"""
		abs_path = self.abspath
		existed = True
		if not isfile(abs_path):
			existed = False
			open(abs_path, 'wb').write(Object.NULL_HEX_SHA)
		# END quick create 
		
		# do it safely by specifying the old value
		try:
			self.repo.git.update_ref(self.path, ref, (existed and self._get_object().hexsha) or None)
		except:
			if not existed:
				os.remove(abs_path)
			# END remove file on error if it didn't exist before
			raise
		# END exception handling
		
	object = property(_get_object, _set_object, doc="Return the object our ref currently refers to")
		
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
