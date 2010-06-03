"""Contains implementations of database retrieveing objects"""
from git.utils import IndexFileSHA1Writer
from git.errors import (
	InvalidDBRoot, 
	BadObject, 
	BadObjectType
	)

from utils import (
		DecompressMemMapReader,
		FDCompressedSha1Writer,
		ENOENT,
		to_hex_sha,
		exists,
		hex_to_bin,
		isdir,
		mkdir,
		rename,
		dirname,
		join
	)

from fun import ( 
	chunk_size,
	loose_object_header_info, 
	write_object
	)

import tempfile
import mmap
import os


class iObjectDBR(object):
	"""Defines an interface for object database lookup.
	Objects are identified either by hex-sha (40 bytes) or 
	by sha (20 bytes)"""
	__slots__ = tuple()
	
	def __contains__(self, sha):
		return self.has_obj
	
	#{ Query Interface 
	def has_object(self, sha):
		"""
		:return: True if the object identified by the given 40 byte hexsha or 20 bytes
			binary sha is contained in the database
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
		
	def object(self, sha):
		"""
		:return: tuple(type_string, size_in_bytes, stream) a tuple with object
			information including its type, its size as well as a stream from which its
			contents can be read
		:param sha: 40 bytes hexsha or 20 bytes binary sha
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
		
	def object_info(self, sha):
		"""
		:return: tuple(type_string, size_in_bytes) tuple with the object's type 
			string as well as its size in bytes
		:param sha: 40 bytes hexsha or 20 bytes binary sha
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
			
	#} END query interface
	
class iObjectDBW(object):
	"""Defines an interface to create objects in the database"""
	__slots__ = tuple()
	
	#{ Edit Interface
	
	def to_object(self, type, size, stream, dry_run=False, sha_as_hex=True):
		"""Create a new object in the database
		:return: the sha identifying the object in the database
		:param type: type string identifying the object
		:param size: size of the data to read from stream
		:param stream: stream providing the data
		:param dry_run: if True, the object database will not actually be changed
		:param sha_as_hex: if True, the returned sha identifying the object will be 
			hex encoded, not binary
		:raise IOError: if data could not be written"""
		raise NotImplementedError("To be implemented in subclass")
	
	def to_objects(self, iter_info, dry_run=False, sha_as_hex=True, max_threads=0):
		"""Create multiple new objects in the database
		:return: sequence of shas identifying the created objects in the order in which 
			they where given.
		:param iter_info: iterable yielding tuples containing the type_string
			size_in_bytes and the steam with the content data.
		:param dry_run: see ``to_obj``
		:param sha_as_hex: see ``to_obj``
		:param max_threads: if < 1, any number of threads may be started while processing
			the request, otherwise the given number of threads will be started.
		:raise IOError: if data could not be written"""
		# a trivial implementation, ignoring the threads for now
		# TODO: add configuration to the class to determine whether we may 
		# actually use multiple threads, default False of course. If the add
		shas = list()
		for args in iter_info:
			shas.append(self.to_object(*args, dry_run=dry_run, sha_as_hex=sha_as_hex))
		return shas
		
	#} END edit interface
	

class FileDBBase(object):
	"""Provides basic facilities to retrieve files of interest, including 
	caching facilities to help mapping hexsha's to objects"""
	__slots__ = ('_root_path', )
	
	def __init__(self, root_path):
		"""Initialize this instance to look for its files at the given root path
		All subsequent operations will be relative to this path
		:raise InvalidDBRoot: 
		:note: The base will perform basic checking for accessability, but the subclass
			is required to verify that the root_path contains the database structure it needs"""
		if not os.path.isdir(root_path):
			raise InvalidDBRoot(root_path)
		self._root_path = root_path
		
		
	#{ Interface 
	def root_path(self):
		""":return: path at which this db operates"""
		return self._root_path
	
	def db_path(self, rela_path):
		"""
		:return: the given relative path relative to our database root, allowing 
			to pontentially access datafiles"""
		return join(self._root_path, rela_path)
	#} END interface
		
	#{ Utiltities
	
		
	#} END utilities
	
	
class LooseObjectDB(FileDBBase, iObjectDBR, iObjectDBW):
	"""A database which operates on loose object files"""
	__slots__ = ('_hexsha_to_file', '_fd_open_flags')
	# CONFIGURATION
	# chunks in which data will be copied between streams
	stream_chunk_size = chunk_size
	
	
	def __init__(self, root_path):
		super(LooseObjectDB, self).__init__(root_path)
		self._hexsha_to_file = dict()
		# Additional Flags - might be set to 0 after the first failure
		# Depending on the root, this might work for some mounts, for others not, which
		# is why it is per instance
		self._fd_open_flags = os.O_NOATIME
	
	#{ Interface 
	def object_path(self, hexsha):
		"""
		:return: path at which the object with the given hexsha would be stored, 
			relative to the database root"""
		return join(hexsha[:2], hexsha[2:])
	
	def readable_db_object_path(self, hexsha):
		"""
		:return: readable object path to the object identified by hexsha
		:raise BadObject: If the object file does not exist"""
		try:
			return self._hexsha_to_file[hexsha]
		except KeyError:
			pass
		# END ignore cache misses 
			
		# try filesystem
		path = self.db_path(self.object_path(hexsha))
		if exists(path):
			self._hexsha_to_file[hexsha] = path
			return path
		# END handle cache
		raise BadObject(hexsha)
		
	#} END interface
	
	def _map_loose_object(self, sha):
		"""
		:return: memory map of that file to allow random read access
		:raise BadObject: if object could not be located"""
		db_path = self.db_path(self.object_path(to_hex_sha(sha)))
		try:
			fd = os.open(db_path, os.O_RDONLY|self._fd_open_flags)
		except OSError,e:
			if e.errno != ENOENT:
				# try again without noatime
				try:
					fd = os.open(db_path, os.O_RDONLY)
				except OSError:
					raise BadObject(to_hex_sha(sha))
				# didn't work because of our flag, don't try it again
				self._fd_open_flags = 0
			else:
				raise BadObject(to_hex_sha(sha))
			# END handle error
		# END exception handling
		try:
			return mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
		finally:
			os.close(fd)
		# END assure file is closed
			
	def object_info(self, sha):
		m = self._map_loose_object(sha)
		try:
			return loose_object_header_info(m)
		finally:
			m.close()
		# END assure release of system resources
		
	def object(self, sha):
		m = self._map_loose_object(sha)
		reader = DecompressMemMapReader(m, close_on_deletion = True)
		type, size = reader.initialize()
		
		return type, size, reader
		
	def has_object(self, sha):
		try:
			self.readable_db_object_path(to_hex_sha(sha))
			return True
		except BadObject:
			return False
		# END check existance
	
	def to_object(self, type, size, stream, dry_run=False, sha_as_hex=True):
		# open a tmp file to write the data to
		fd, tmp_path = tempfile.mkstemp(prefix='obj', dir=self._root_path)
		writer = FDCompressedSha1Writer(fd)
	
		try:
			write_object(type, size, stream, writer,
							close_target_stream=True, chunk_size=self.stream_chunk_size)
		except:
			os.remove(tmp_path)
			raise
		# END assure tmpfile removal on error
		
		
		# in dry-run mode, we delete the file afterwards
		sha = writer.sha(as_hex=True)
		
		if dry_run:
			os.remove(tmp_path)
		else:
			# rename the file into place
			obj_path = self.db_path(self.object_path(sha))
			obj_dir = dirname(obj_path)
			if not isdir(obj_dir):
				mkdir(obj_dir)
			# END handle destination directory
			rename(tmp_path, obj_path)
		# END handle dry_run
		
		if not sha_as_hex:
			sha = hex_to_bin(sha)
		# END handle sha format
		
		return sha
	
	
class PackedDB(FileDBBase, iObjectDBR):
	"""A database operating on a set of object packs"""
	
	
class CompoundDB(iObjectDBR):
	"""A database which delegates calls to sub-databases"""
	

class ReferenceDB(CompoundDB):
	"""A database consisting of database referred to in a file"""
	
	
class GitObjectDB(CompoundDB, iObjectDBW):
	"""A database representing the default git object store, which includes loose 
	objects, pack files and an alternates file
	
	It will create objects only in the loose object database."""
	
