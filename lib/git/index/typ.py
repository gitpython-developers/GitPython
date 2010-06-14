"""Module with additional types used by the index"""

from util import (
					pack, 
					unpack
				)

__all__ = ('BlobFilter', 'BaseIndexEntry', 'IndexEntry')

class BlobFilter(object):
	"""
	Predicate to be used by iter_blobs allowing to filter only return blobs which
	match the given list of directories or files.

	The given paths are given relative to the repository.
	"""
	__slots__ = 'paths'

	def __init__(self, paths):
		""":param paths:
			tuple or list of paths which are either pointing to directories or
			to files relative to the current repository
		"""
		self.paths = paths

	def __call__(self, stage_blob):
		path = stage_blob[1].path
		for p in self.paths:
			if path.startswith(p):
				return True
		# END for each path in filter paths
		return False


class BaseIndexEntry(tuple):
	"""Small Brother of an index entry which can be created to describe changes
	done to the index in which case plenty of additional information is not requried.

	As the first 4 data members match exactly to the IndexEntry type, methods
	expecting a BaseIndexEntry can also handle full IndexEntries even if they
	use numeric indices for performance reasons. """

	def __str__(self):
		return "%o %s %i\t%s" % (self.mode, self.sha, self.stage, self.path)

	@property
	def mode(self):
		""" File Mode, compatible to stat module constants """
		return self[0]

	@property
	def sha(self):
		""" hex sha of the blob """
		return self[1]

	@property
	def stage(self):
		"""Stage of the entry, either:
		
			0 = default stage
			1 = stage before a merge or common ancestor entry in case of a 3 way merge
			2 = stage of entries from the 'left' side of the merge
			3 = stage of entries from the right side of the merge
		
		:note: For more information, see http://www.kernel.org/pub/software/scm/git/docs/git-read-tree.html
		"""
		return self[2]

	@property
	def path(self):
		""":return: our path relative to the repository working tree root"""
		return self[3]

	@classmethod
	def from_blob(cls, blob, stage = 0):
		""":return: Fully equipped BaseIndexEntry at the given stage"""
		return cls((blob.mode, blob.sha, stage, blob.path))


class IndexEntry(BaseIndexEntry):
	"""Allows convenient access to IndexEntry data without completely unpacking it.

	Attributes usully accessed often are cached in the tuple whereas others are
	unpacked on demand.

	See the properties for a mapping between names and tuple indices. """
	@property
	def ctime(self):
		""":return:
			Tuple(int_time_seconds_since_epoch, int_nano_seconds) of the
			file's creation time
		"""
		return unpack(">LL", self[4])

	@property
	def mtime(self):
		"""See ctime property, but returns modification time """
		return unpack(">LL", self[5])

	@property
	def dev(self):
		""" Device ID """
		return self[6]

	@property
	def inode(self):
		""" Inode ID """
		return self[7]

	@property
	def uid(self):
		""" User ID """
		return self[8]

	@property
	def gid(self):
		""" Group ID """
		return self[9]

	@property
	def size(self):
		""":return: Uncompressed size of the blob """
		return self[10]

	@classmethod
	def from_base(cls, base):
		""" 
		:return:
			Minimal entry as created from the given BaseIndexEntry instance.
			Missing values will be set to null-like values

		:param base: Instance of type BaseIndexEntry"""
		time = pack(">LL", 0, 0)
		return IndexEntry((base.mode, base.sha, base.stage, base.path, time, time, 0, 0, 0, 0, 0))

	@classmethod
	def from_blob(cls, blob):
		""":return: Minimal entry resembling the given blob objecft"""
		time = pack(">LL", 0, 0)
		return IndexEntry((blob.mode, blob.sha, 0, blob.path, time, time, 0, 0, 0, 0, blob.size))


