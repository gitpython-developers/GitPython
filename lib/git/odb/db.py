"""Contains implementations of database retrieveing objects"""
import os
from git.errors import (
	InvalidDBRoot, 
	BadObject
	)
from git.utils import IndexFileSHA1Writer

from utils import (
		getsize,
		to_hex_sha,
		exists,
		hex_to_bin,
		FDCompressedSha1Writer,
		isdir,
		mkdir,
		rename,
		dirname,
		join
	)

import tempfile
import mmap


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
			binary sha is contained in the database"""
		raise NotImplementedError("To be implemented in subclass")
		
	def object(self, sha):
		"""
		:return: tuple(type_string, size_in_bytes, stream) a tuple with object
			information including its type, its size as well as a stream from which its
			contents can be read
		:param sha: 40 bytes hexsha or 20 bytes binary sha  """
		raise NotImplementedError("To be implemented in subclass")
		
	def object_info(self, sha):
		"""
		:return: tuple(type_string, size_in_bytes) tuple with the object's type 
			string as well as its size in bytes
		:param sha: 40 bytes hexsha or 20 bytes binary sha"""
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
			hex encoded, not binary"""
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
			the request, otherwise the given number of threads will be started."""
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
	__slots__ = ('_hexsha_to_file', )
	
	# CONFIGURATION
	# chunks in which data will be copied between streams
	stream_chunk_size = 1000*1000
	
	def __init__(self, root_path):
		super(LooseObjectDB, self).__init__(root_path)
		self._hexsha_to_file = dict()
	
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
	
	def _object_header_info(self, mmap):
		""":return: tuple(type_string, uncompressed_size_in_bytes 
		:param mmap: newly mapped memory map at position 0. It will be 
			seeked to the actual start of the object contents, which can be used
			to initialize a zlib decompress object."""
		raise NotImplementedError("todo")
	
	def _map_object(self, sha):
		"""
		:return: tuple(file, mmap) tuple with an opened file for reading, and 
			a memory map of that file"""
		db_path = self.readable_db_object_path(to_hex_sha(sha))
		f = open(db_path, 'rb')
		m = mmap.mmap(f.fileno(), getsize(db_path), access=mmap.ACCESS_READ)
		return (f, m)
			
	def object_info(self, sha):
		f, m = self._map_object(sha)
		try:
			type, size = self._object_header_info(m)
		finally:
			f.close()
			m.close()
		# END assure release of system resources
		
	def object(self, sha):
		f, m = self._map_object(sha)
		type, size = self._object_header_info(m)
		# TODO: init a dynamic decompress stream from our memory map
		
		
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
		
		# WRITE HEADER: type SP size NULL
		writer.write("%s %i%s" % (type, size, chr(0)))
		
		# WRITE ALL DATA
		chunksize = self.stream_chunk_size
		try:
			try:
				while True:
					data_len = writer.write(stream.read(chunksize))
					if data_len < chunksize:
						# WRITE FOOTER
						writer.write('\n')
						break
					# END check for stream end
				# END duplicate data
			finally:
				writer.close()
			# END assure file was closed
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
	
