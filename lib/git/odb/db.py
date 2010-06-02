"""Contains implementations of database retrieveing objects"""
import os
from git.errors import InvalidDBRoot


class iObjectDBR(object):
	"""Defines an interface for object database lookup.
	Objects are identified either by hex-sha (40 bytes) or 
	by sha (20 bytes)"""
	__slots__ = tuple()
	
	#{ Query Interface 
	def has_obj_hex(self, hexsha):
		""":return: True if the object identified by the given 40 byte hexsha is 
		contained in the database"""
		raise NotImplementedError("To be implemented in subclass")
		
	def has_obj_bin(self, sha):
		""":return: as ``has_obj_hex``, but takes a 20 byte binary sha"""
		raise NotImplementedError("To be implemented in subclass")
		
	def obj_hex(self, hexsha):
		""":return: tuple(type_string, size_in_bytes, stream) a tuple with object
		information including its type, its size as well as a stream from which its
		contents can be read"""
		raise NotImplementedError("To be implemented in subclass")
		
	def obj_bin(self, sha):
		""":return: as in ``obj_hex``, but takes a binary sha"""
		raise NotImplementedError("To be implemented in subclass")
		
	def obj_info_hex(self, hexsha):
		""":return: tuple(type_string, size_in_bytes) tuple with the object's type 
			string as well as its size in bytes"""
		raise NotImplementedError("To be implemented in subclass")
			
	#} END query interface
	
class iObjectDBW(object):
	"""Defines an interface to create objects in the database"""
	__slots__ = tuple()
	
	#{ Edit Interface
	
	def to_obj(self, type, size, stream, dry_run=False, sha_as_hex=True):
		"""Create a new object in the database
		:return: the sha identifying the object in the database
		:param type: type string identifying the object
		:param size: size of the data to read from stream
		:param stream: stream providing the data
		:param dry_run: if True, the object database will not actually be changed
		:param sha_as_hex: if True, the returned sha identifying the object will be 
			hex encoded, not binary"""
		raise NotImplementedError("To be implemented in subclass")
	
	def to_objs(self, iter_info, dry_run=False, sha_as_hex=True, max_threads=0):
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
			shas.append(self.to_obj(*args, dry_run=dry_run, sha_as_hex=sha_as_hex))
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
	
	#} END interface
		
	#{ Utiltities
	def _root_rela_path(self, rela_path):
		""":return: the given relative path relative to our database root"""
		return os.path.join(self._root_path, rela_path)
		
	#} END utilities
	
	
class LooseObjectDB(FileDBBase, iObjectDBR, iObjectDBW):
	"""A database which operates on loose object files"""
	
	
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
	
