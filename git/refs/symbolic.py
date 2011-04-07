from gitdb.ref.symbolic import SymbolicReference as GitDB_SymbolicReference
from git.util import RepoAliasMixin
__all__ = ["SymbolicReference"]

class SymbolicReference(GitDB_SymbolicReference, RepoAliasMixin):
	__slots__ = tuple()
	pass
