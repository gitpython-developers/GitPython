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

class IndexEntry(tuple):
	"""
	Allows convenient access to IndexEntry data without completely unpacking it.
	
	Attributes usully accessed often are cached in the tuple whereas others are 
	unpacked on demand.
	
	See the properties for a mapping between names and tuple indices.
	"""
	@property
	def path(self):
		return self[0]
	
	@property
	def ctime(self):
		"""
		Returns
			Tuple(int_time_seconds_since_epoch, int_nano_seconds) of the 
			file's creation time
		"""
		return struct.unpack(">LL", self[1])
		
	@property
	def mtime(self):
		"""
		See ctime property, but returns modification time
		"""
		return struct.unpack(">LL", self[2])
	
	@property
	def dev(self):
		return self[3] 
	
	@property
	def inode(self):
		return self[4]
		
	@property
	def mode(self):
		return self[5]
		
	@property
	def uid(self):
		return self[6]
		
	@property
	def gid(self):
		return self[7]

	@property
	def size(self):
		return self[8]
		
	@property
	def sha(self):
		return self[9]
		
	@property
	def stage(self):
		return self[10]


class Index(object):
	"""
	Implements an Index that can be manipulated using a native implementation in 
	order to save git command function calls wherever possible.
	
	It provides custom merging facilities and to create custom commits.
	"""
	__slots__ = ( "version", "entries" )
	
	def __init__(self, stream = None):
		"""
		Initialize this Index instance, optionally from the given ``stream``
		
		Note
			Reading is based on the dulwich project.
		"""
		self.entries = dict()
		self.version = -1
		if stream is not None:
			self._read_from_stream(stream)
	
	def _read_entry(self, stream):
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
		return IndexEntry((path, ctime, mtime, dev, ino, mode, uid, gid, size, 
				binascii.hexlify(sha), flags >> 12))
		
	
	def _read_header(self, stream):
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
		"""
		self.version, num_entries = self._read_header(stream)
		self.entries = dict()
		count = 0
		while count < num_entries:
			entry = self._read_entry(stream)
			self.entries[(entry.path,entry.stage)] = entry
			count += 1
		# END for each entry
	
	@classmethod
	def from_file(cls, file_path):
		"""
		Returns
			Index instance as recreated from the given stream.
			
		``file_pa ``
			File path pointing to git index file
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
		
	def write(self, stream):
		"""
		Write the current state to the given stream
		
		``stream``
			File-like object
		
		Returns
			self
		"""
		raise NotImplementedError( "TODO" )
