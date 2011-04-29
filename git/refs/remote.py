import os
from gitdb.ref.remote import RemoteReference as GitDB_RemoteReference

__all__ = ["RemoteReference"]

	
class RemoteReference(GitDB_RemoteReference):
	"""Represents a reference pointing to a remote head."""
	__slots__ = tuple()
	
	@classmethod
	def delete(cls, repo, *refs, **kwargs):
		"""Delete the given remote references.
		:note:
			kwargs are given for compatability with the base class method as we 
			should not narrow the signature."""
		repo.git.branch("-d", "-r", *refs)
		# the official deletion method will ignore remote symbolic refs - these 
		# are generally ignored in the refs/ folder. We don't though 
		# and delete remainders manually
		for ref in refs:
			try:
				os.remove(join(repo.git_dir, ref.path))
			except OSError:
				pass
		# END for each ref
