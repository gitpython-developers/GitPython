
from gitdb.ref.reference import Reference as GitDB_Reference
from git.util import RepoAliasMixin
__all__ = ["Reference"]

class Reference(GitDB_Reference, RepoAliasMixin):
	__slots__ = tuple()
	pass
