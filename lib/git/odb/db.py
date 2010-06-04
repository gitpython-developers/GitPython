"""Contains implementations of database retrieveing objects"""
from git.utils import IndexFileSHA1Writer
from git.errors import (
	InvalidDBRoot, 
	BadObject, 
	BadObjectType
	)

from stream import (
		DecompressMemMapReader,
		FDCompressedSha1Writer
	)

from utils import (
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


class ObjectDBR(object):
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
		
	def info(self, sha):
		""" :return: ODB_Info instance
		:param sha: 40 bytes hexsha or 20 bytes binary sha
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
		
	def info_async(self, input_channel):
		"""Retrieve information of a multitude of objects asynchronously
		:param input_channel: Channel yielding the sha's of the objects of interest
		:return: Channel yielding ODB_Info|InvalidODB_Info, in any order"""
		raise NotImplementedError("To be implemented in subclass")
		
	def stream(self, sha):
		""":return: ODB_OStream instance
		:param sha: 40 bytes hexsha or 20 bytes binary sha
		:raise BadObject:"""
		raise NotImplementedError("To be implemented in subclass")
		
	def stream_async(self, input_channel):
		"""Retrieve the ODB_OStream of multiple objects
		:param input_channel: see ``info``
		:param max_threads: see ``ObjectDBW.store``
		:return: Channel yielding ODB_OStream|InvalidODB_OStream instances in any order"""
		raise NotImplementedError("To be implemented in subclass")
			
	#} END query interface
	
class ObjectDBW(object):
	"""Defines an interface to create objects in the database"""
	__slots__ = "_ostream"
	
	def __init__(self, *args, **kwargs):
		self._ostream = None
	
	#{ Edit Interface
	def set_ostream(self, stream):
		"""Adjusts the stream to which all data should be sent when storing new objects
		:param stream: if not None, the stream to use, if None the default stream
			will be used.
		:return: previously installed stream, or None if there was no override
		:raise TypeError: if the stream doesn't have the supported functionality"""
		cstream = self._ostream
		self._ostream = stream
		return cstream
		
	def ostream(self):
		""":return: overridden output stream this instance will write to, or None
			if it will write to the default stream"""
			return self._ostream
	
	def store(self, istream):
		"""Create a new object in the database
		:return: the input istream object with its sha set to its corresponding value
		:param istream: ODB_IStream compatible instance. If its sha is already set 
			to a value, the object will just be stored in the our database format, 
			in which case the input stream is expected to be in object format ( header + contents ).
		:raise IOError: if data could not be written"""
		raise NotImplementedError("To be implemented in subclass")
	
	def store_async(self, input_channel):
		"""Create multiple new objects in the database asynchronously. The method will 
		return right away, returning an output channel which receives the results as 
		they are computed.
		
		:return: Channel yielding your ODB_IStream which served as input, in any order.
			The IStreams sha will be set to the sha it received during the process, 
			or its error attribute will be set to the exception informing about the error.
		:param input_channel: Channel yielding ODB_IStream instance.
			As the same instances will be used in the output channel, you can create a map
			between the id(istream) -> istream
		:note:As some ODB implementations implement this operation as atomic, they might 
			abort the whole operation if one item could not be processed. Hence check how 
			many items have actually been produced."""
		# a trivial implementation, ignoring the threads for now
		# TODO: add configuration to the class to determine whether we may 
		# actually use multiple threads, default False of course. If the add
		shas = list()
		for args in iter_info:
			shas.append(self.store(dry_run=dry_run, sha_as_hex=sha_as_hex, *args))
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
		super(FileDBBase, self).__init__()
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
	
	
class LooseObjectDB(FileDBBase, ObjectDBR, ObjectDBW):
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
		self._fd_open_flags = getattr(os, 'O_NOATIME', 0)
	
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
			
	def info(self, sha):
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
	
	def store(self, istream):
		# open a tmp file to write the data to
		# todo: implement ostream properly
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
	
	
class PackedDB(FileDBBase, ObjectDBR):
	"""A database operating on a set of object packs"""
	
	
class CompoundDB(ObjectDBR):
	"""A database which delegates calls to sub-databases"""
	

class ReferenceDB(CompoundDB):
	"""A database consisting of database referred to in a file"""
	
	
#class GitObjectDB(CompoundDB, ObjectDBW):
class GitObjectDB(LooseObjectDB):
	"""A database representing the default git object store, which includes loose 
	objects, pack files and an alternates file
	
	It will create objects only in the loose object database.
	:note: for now, we use the git command to do all the lookup, just until he 
		have packs and the other implementations
	"""
	__slots__ = ('_git', )
	def __init__(self, root_path, git):
		"""Initialize this instance with the root and a git command"""
		super(GitObjectDB, self).__init__(root_path)
		self._git = git
		
	def info(self, sha):
		discard, type, size = self._git.get_object_header(sha)
		return type, size
		
	def object(self, sha):
		"""For now, all lookup is done by git itself"""
		discard, type, size, stream = self._git.stream_object_data(sha)
		return type, size, stream
	
