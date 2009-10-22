# utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import sys
import tempfile

try:
    import hashlib
except ImportError:
    import sha

def make_sha(source=''):
    """
    A python2.4 workaround for the sha/hashlib module fiasco
    
	Note
		From the dulwich project
	"""
    try:
        return hashlib.sha1(source)
    except NameError:
        sha1 = sha.sha(source)
        return sha1


class SHA1Writer(object):
    """
    Wrapper around a file-like object that remembers the SHA1 of 
    the data written to it. It will write a sha when the stream is closed
    or if the asked for explicitly usign write_sha.
    
    Note:
    	Based on the dulwich project
    """
    __slots__ = ("f", "sha1")
    
    def __init__(self, f):
        self.f = f
        self.sha1 = make_sha("")

    def write(self, data):
        self.sha1.update(data)
        self.f.write(data)

    def write_sha(self):
        sha = self.sha1.digest()
        self.f.write(sha)
        return sha

    def close(self):
        sha = self.write_sha()
        self.f.close()
        return sha

    def tell(self):
        return self.f.tell()


class LockFile(object):
	"""
	Provides methods to obtain, check for, and release a file based lock which 
	should be used to handle concurrent access to the same file.
	
	As we are a utility class to be derived from, we only use protected methods.
	
	Locks will automatically be released on destruction
	"""
	__slots__ = ("_file_path", "_owns_lock")
	
	def __init__(self, file_path):
		self._file_path = file_path
		self._owns_lock = False
	
	def __del__(self):
		self._release_lock()
	
	def _lock_file_path(self):
		"""
		Return
			Path to lockfile
		"""
		return "%s.lock" % (self._file_path)
	
	def _has_lock(self):
		"""
		Return
			True if we have a lock and if the lockfile still exists
			
		Raise
			AssertionError if our lock-file does not exist
		"""
		if not self._owns_lock:
			return False
		
		lock_file = self._lock_file_path()
		try:
			fp = open(lock_file, "r")
			pid = int(fp.read())
			fp.close()
		except IOError:
			raise AssertionError("GitConfigParser has a lock but the lock file at %s could not be read" % lock_file)
		
		if pid != os.getpid():
			raise AssertionError("We claim to own the lock at %s, but it was not owned by our process: %i" % (lock_file, os.getpid()))
		
		return True
		
	def _obtain_lock_or_raise(self):
		"""
		Create a lock file as flag for other instances, mark our instance as lock-holder
		
		Raise
			IOError if a lock was already present or a lock file could not be written
		"""
		if self._has_lock():
			return 
			
		lock_file = self._lock_file_path()
		if os.path.exists(lock_file):
			raise IOError("Lock for file %r did already exist, delete %r in case the lock is illegal" % (self._file_path, lock_file))
		
		fp = open(lock_file, "w")
		fp.write(str(os.getpid()))
		fp.close()
		
		self._owns_lock = True
		
	def _release_lock(self):
		"""
		Release our lock if we have one
		"""
		if not self._has_lock():
			return 
			
		os.remove(self._lock_file_path())
		self._owns_lock = False


class ConcurrentWriteOperation(LockFile):
	"""
	This class facilitates a safe write operation to a file on disk such that we: 
	
		- lock the original file
		- write to a temporary file
		- rename temporary file back to the original one on close
		- unlock the original file
		
	This type handles error correctly in that it will assure a consistent state 
	on destruction
	"""
	__slots__ = "_temp_write_fp"
	
	def __init__(self, file_path):
		"""
		Initialize an instance able to write the given file_path
		"""
		super(ConcurrentWriteOperation, self).__init__(file_path)
		self._temp_write_fp = None
	
	def __del__(self):
		self._end_writing(successful=False)
		
	def _begin_writing(self):
		"""
		Begin writing our file, hence we get a lock and start writing 
		a temporary file in the same directory.
		
		Returns
			File Object to write to. It is still maintained by this instance
			and you do not need to manually close 
		"""
		# already writing ? 
		if self._temp_write_fp is not None:
			return self._temp_write_fp
			
		self._obtain_lock_or_raise()
		dirname, basename = os.path.split(self._file_path)
		self._temp_write_fp = open(tempfile.mktemp(basename, '', dirname), "w")
		return self._temp_write_fp
		
	def _is_writing(self):
		"""
		Returns 
			True if we are currently writing a file
		"""
		return self._temp_write_fp is not None
	
	def _end_writing(self, successful=True):
		"""
		Indicate you successfully finished writing the file to:
		
			- close the underlying stream
			- rename the remporary file to the original one
			- release our lock
		"""
		# did we start a write operation ?
		if self._temp_write_fp is None:
			return 
			
		self._temp_write_fp.close()
		if successful:
			# on windows, rename does not silently overwrite the existing one
			if sys.platform == "win32":
				os.remove(self._file_path)
			os.rename(self._temp_write_fp.name, self._file_path)
		else:
			# just delete the file so far, we failed
			os.remove(self._temp_write_fp.name)
		# END successful handling
	
		# finally reset our handle
		self._release_lock()
		self._temp_write_fp = None


class LazyMixin(object):
	"""
	Base class providing an interface to lazily retrieve attribute values upon 
	first access. If slots are used, memory will only be reserved once the attribute
	is actually accessed and retrieved the first time. All future accesses will 
	return the cached value as stored in the Instance's dict or slot.
	"""
	__slots__ = tuple()
	
	def __getattr__(self, attr):
		"""
		Whenever an attribute is requested that we do not know, we allow it 
		to be created and set. Next time the same attribute is reqeusted, it is simply
		returned from our dict/slots.
		"""
		self._set_cache_(attr)
		# will raise in case the cache was not created
		return object.__getattribute__(self, attr)

	def _set_cache_(self, attr):
		""" This method should be overridden in the derived class. 
		It should check whether the attribute named by attr can be created
		and cached. Do nothing if you do not know the attribute or call your subclass
		
		The derived class may create as many additional attributes as it deems 
		necessary in case a git command returns more information than represented 
		in the single attribute."""
		pass


class IterableList(list):
	"""
	List of iterable objects allowing to query an object by id or by named index::
	 
	 heads = repo.heads
	 heads.master
	 heads['master']
	 heads[0]
	"""
	__slots__ = '_id_attr'
	
	def __new__(cls, id_attr):
		return super(IterableList,cls).__new__(cls)
		
	def __init__(self, id_attr):
		self._id_attr = id_attr
		
	def __getattr__(self, attr):
		for item in self:
			if getattr(item, self._id_attr) == attr:
				return item
		# END for each item
		return list.__getattribute__(self, attr)
		
	def __getitem__(self, index):
		if isinstance(index, int):
			return list.__getitem__(self,index)
		
		try:
			return getattr(self, index)
		except AttributeError:
			raise IndexError( "No item found with id %r" % index )

class Iterable(object):
	"""
	Defines an interface for iterable items which is to assure a uniform 
	way to retrieve and iterate items within the git repository
	"""
	__slots__ = tuple()
	_id_attribute_ = "attribute that most suitably identifies your instance"
	
	@classmethod
	def list_items(cls, repo, *args, **kwargs):
		"""
		Find all items of this type - subclasses can specify args and kwargs differently.
		If no args are given, subclasses are obliged to return all items if no additional 
		arguments arg given.
		
		Note: Favor the iter_items method as it will 
		
		Returns:
			list(Item,...) list of item instances 
		"""
		#return list(cls.iter_items(repo, *args, **kwargs))
		out_list = IterableList( cls._id_attribute_ )
		out_list.extend(cls.iter_items(repo, *args, **kwargs))
		return out_list
		
		
	@classmethod
	def iter_items(cls, repo, *args, **kwargs):
		"""
		For more information about the arguments, see list_items
		Return: 
			iterator yielding Items
		"""
		raise NotImplementedError("To be implemented by Subclass")
		
