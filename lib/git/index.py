# index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing Index implementation, allowing to perform all kinds of index
manipulations such as querying and merging.
"""
import struct
import binascii
import mmap
import objects
import tempfile
import os

class IndexEntry(tuple):
	"""
	Allows convenient access to IndexEntry data without completely unpacking it.
	
	Attributes usully accessed often are cached in the tuple whereas others are 
	unpacked on demand.
	
	See the properties for a mapping between names and tuple indices.
	"""
	@property
	def ctime(self):
		"""
		Returns
			Tuple(int_time_seconds_since_epoch, int_nano_seconds) of the 
			file's creation time
		"""
		return struct.unpack(">LL", self[0])
		
	@property
	def mtime(self):
		"""
		See ctime property, but returns modification time
		"""
		return struct.unpack(">LL", self[1])
	
	@property
	def dev(self):
		"""
		Device ID
		"""
		return self[2] 
	
	@property
	def inode(self):
		"""
		Inode ID
		"""
		return self[3]
		
	@property
	def mode(self):
		"""
		File Mode, compatible to stat module constants
		"""
		return self[4]
		
	@property
	def uid(self):
		"""
		User ID
		"""
		return self[5]
		
	@property
	def gid(self):
		"""
		Group ID
		"""
		return self[6]

	@property
	def size(self):
		"""
		Uncompressed size of the blob
		
		Note
			Will be 0 if the stage is not 0 ( hence it is an unmerged entry )
		"""
		return self[7]
		
	@property
	def sha(self):
		"""
		hex sha of the blob
		"""
		return self[8]
		
	@property
	def stage(self):
		"""
		Stage of the entry, either:
			0 = default stage
			1 = stage before a merge or common ancestor entry in case of a 3 way merge
			2 = stage of entries from the 'left' side of the merge
			3 = stage of entries from the right side of the merge
		Note:
			For more information, see http://www.kernel.org/pub/software/scm/git/docs/git-read-tree.html
		"""
		return self[9]

	@property
	def path(self):
		return self[10]


class Index(object):
	"""
	Implements an Index that can be manipulated using a native implementation in 
	order to save git command function calls wherever possible.
	
	It provides custom merging facilities and to create custom commits.
	
	``Entries``
	The index contains an entries dict whose keys are tuples of type IndexEntry
	to facilitate access.
	"""
	__slots__ = ( "version", "entries", "_extension_data" )
	_VERSION = 2			# latest version we support
	
	def __init__(self, stream = None):
		"""
		Initialize this Index instance, optionally from the given ``stream``
		"""
		self.entries = dict()
		self.version = self._VERSION
		self._extension_data = ''
		if stream is not None:
			self._read_from_stream(stream)
	
	@classmethod
	def _read_entry(cls, stream):
		"""Return: One entry of the given stream"""
		beginoffset = stream.tell()
		ctime = struct.unpack(">8s", stream.read(8))[0]
		mtime = struct.unpack(">8s", stream.read(8))[0]
		(dev, ino, mode, uid, gid, size, sha, flags) = \
			struct.unpack(">LLLLLL20sH", stream.read(20 + 4 * 6 + 2))
		path_size = flags & 0x0fff
		path = stream.read(path_size)
		
		real_size = ((stream.tell() - beginoffset + 8) & ~7)
		data = stream.read((beginoffset + real_size) - stream.tell())
		return IndexEntry((ctime, mtime, dev, ino, mode, uid, gid, size, 
				binascii.hexlify(sha), flags >> 12, path))
		
	@classmethod
	def _read_header(cls, stream):
		"""Return tuple(version_long, num_entries) from the given stream"""
		type_id = stream.read(4)
		if type_id != "DIRC":
			raise AssertionError("Invalid index file header: %r" % type_id)
		version, num_entries = struct.unpack(">LL", stream.read(4 * 2))
		assert version in (1, 2)
		return version, num_entries
		
	def _read_from_stream(self, stream):
		"""
		Initialize this instance with index values read from the given stream
		
		Note
			We explicitly do not clear the entries dict here to allow for reading 
			multiple chunks from multiple streams into the same Index instance
		"""
		self.version, num_entries = self._read_header(stream)
		count = 0
		while count < num_entries:
			entry = self._read_entry(stream)
			self.entries[(entry.path,entry.stage)] = entry
			count += 1
		# END for each entry
		# this data chunk is the footer of the index, don't yet know what it is for
		self._extension_data = stream.read(~0)
	
	@classmethod
	def from_file(cls, file_path):
		"""
		Returns
			Index instance as recreated from the given stream.
			
		``file_pa ``
			File path pointing to git index file
			
		Note
			Reading is based on the dulwich project.
		"""
		fp = open(file_path, "r")
		
		# try memory map for speed
		stream = fp
		try:
			stream = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
		except Exception:
			pass
		# END memory mapping
		
		try:
			return cls(stream)
		finally:
			fp.close()
		
	
	@classmethod
	def to_file(cls, index, file_path):
		"""
		Write the index data to the given file path.
		
		``index``
			Index you wish to write.
			
		``file_path``
			Path at which to write the index data. Please note that missing directories
			will lead to an exception to be thrown.
			
		Raise 
			IOError if the file could not be written
		"""
		fp = open(file_path, "w")
		try:
			return index.write(fp)
		finally:
			fp.close()
		# END exception handling
		

	@classmethod
	def _write_cache_entry(cls, stream, entry):
		"""
		Write an IndexEntry to a stream
		"""
		beginoffset = stream.tell()
		stream.write(entry[0])			# ctime
		stream.write(entry[1])			# mtime
		path = entry[10]
		plen = len(path) & 0x0fff		# path length
		assert plen == len(path), "Path %s too long to fit into index" % entry[10]
		flags = plen | (entry[9] << 12)# stage and path length are 2 byte flags
		stream.write(struct.pack(">LLLLLL20sH", entry[2], entry[3], entry[4], 
									entry[5], entry[6], entry[7], binascii.unhexlify(entry[8]), flags))
		stream.write(path)
		real_size = ((stream.tell() - beginoffset + 8) & ~7)
		stream.write("\0" * ((beginoffset + real_size) - stream.tell()))

	def write(self, stream):
		"""
		Write the current state to the given stream
		
		``stream``
			File-like object
		
		Returns
			self
		
		Note
			Index writing based on the dulwich implementation
		"""
		# header
		stream.write("DIRC")
		stream.write(struct.pack(">LL", self.version, len(self.entries)))
		
		# body
		entries_sorted = self.entries.values()
		entries_sorted.sort(key=lambda e: (e[10], e[9]))		# use path/stage as sort key
		for entry in entries_sorted:
			self._write_cache_entry(stream, entry)
		# END for each entry
		# write extension_data which we currently cannot interprete
		stream.write(self._extension_data)
		
	
	@classmethod
	def from_tree(cls, repo, *treeish, **kwargs):
		"""
		Merge the given treeish revisions into a new index which is returned.
		The original index will remain unaltered
		
		``repo``
			The repository treeish are located in.
			
		``*treeish``
			One, two or three Tree Objects or Commits. The result changes according to the 
			amoutn of trees.
			If 1 Tree is given, it will just be read into a new index
			If 2 Trees are given, they will be merged into a new index using a 
			 two way merge algorithm. Tree 1 is the 'current' tree, tree 2 is the 'other'
			 one. It behaves like a fast-forward.
			If 3 Trees are given, a 3-way merge will be performed with the first tree
			 being the common ancestor of tree 2 and tree 3. Tree 2 is the 'current' tree, 
			 tree 3 is the 'other' one
			 
		``**kwargs``
			Additional arguments passed to git-read-tree
			
		Note:
			In the three-way merge case, --aggressive will be specified to automatically
			resolve more cases in a commonly correct manner. Specify trivial=True as kwarg
			to override that.
		"""
		if len(treeish) == 0 or len(treeish) > 3:
			raise ValueError("Please specify between 1 and 3 treeish, got %i" % len(treeish))
		
		arg_list = list()
		# ignore that working tree and index possibly are out of date
		if len(treeish)>1:
			# drop unmerged entries when reading our index and merging
			arg_list.append("--reset")	
			# handle non-trivial cases the way a real merge does
			arg_list.append("--aggressive")	
		# END merge handling
		
		# tmp file created in git home directory to be sure renaming 
		# works - /tmp/ dirs could be on another device
		tmp_index = tempfile.mktemp('','',repo.path)
		arg_list.append("--index-output=%s" % tmp_index)
		arg_list.extend(treeish)
		
		# move current index out of the way - otherwise the merge may fail
		# as it considers existing entries. moving it essentially clears the index.
		# Unfortunately there is no 'soft' way to do it
		cur_index = os.path.join(repo.path, 'index')
		moved_index = os.path.join(repo.path, 'index_moved'+tempfile.mktemp('','',''))
		try:
			os.rename(cur_index, moved_index)
			repo.git.read_tree(*arg_list, **kwargs)
			index = cls.from_file(tmp_index)
		finally:
			# put back the original index first !
			if os.path.exists(moved_index):
				os.rename(moved_index, cur_index)
			if os.path.exists(tmp_index):
				os.remove(tmp_index)
		# END index merge handling
		
		return index
		
	def write_tree(self, stream):
		"""
		Writes the 
		"""
		raise NotImplementedError("TODO")
		
	
