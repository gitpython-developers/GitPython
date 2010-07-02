# utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import sys
import time
import tempfile

from gitdb.util import (
							make_sha, 
							LockedFD, 
							file_contents_ro, 
							LazyMixin, 
							to_hex_sha, 
							to_bin_sha
						)

__all__ = ( "stream_copy", "join_path", "to_native_path_windows", "to_native_path_linux", 
			"join_path_native", "Stats", "IndexFileSHA1Writer", "Iterable", "IterableList", 
			"BlockingLockFile", "LockFile" )

def stream_copy(source, destination, chunk_size=512*1024):
	"""Copy all data from the source stream into the destination stream in chunks
	of size chunk_size
	
	:return: amount of bytes written"""
	br = 0
	while True:
		chunk = source.read(chunk_size)
		destination.write(chunk)
		br += len(chunk)
		if len(chunk) < chunk_size:
			break
	# END reading output stream
	return br

def join_path(a, *p):
	"""Join path tokens together similar to os.path.join, but always use 
	'/' instead of possibly '\' on windows."""
	path = a
	for b in p:
		if b.startswith('/'):
			path += b[1:]
		elif path == '' or path.endswith('/'):
			path +=	 b
		else:
			path += '/' + b
	return path
	
def to_native_path_windows(path):
	return path.replace('/','\\')
	
def to_native_path_linux(path):
	return path.replace('\\','/')

if sys.platform.startswith('win'):
	to_native_path = to_native_path_windows
else:
	# no need for any work on linux
	def to_native_path_linux(path):
		return path
	to_native_path = to_native_path_linux

def join_path_native(a, *p):
	"""As join path, but makes sure an OS native path is returned. This is only 
	needed to play it safe on my dear windows and to assure nice paths that only 
	use '\'"""
	return to_native_path(join_path(a, *p))


class Stats(object):
	"""
	Represents stat information as presented by git at the end of a merge. It is 
	created from the output of a diff operation.
	
	``Example``::
	
	 c = Commit( sha1 )
	 s = c.stats
	 s.total		 # full-stat-dict
	 s.files		 # dict( filepath : stat-dict )
	 
	``stat-dict``
	
	A dictionary with the following keys and values::
	 
	  deletions = number of deleted lines as int
	  insertions = number of inserted lines as int
	  lines = total number of lines changed as int, or deletions + insertions
	  
	``full-stat-dict``
	
	In addition to the items in the stat-dict, it features additional information::
	
	 files = number of changed files as int"""
	__slots__ = ("total", "files")
	
	def __init__(self, total, files):
		self.total = total
		self.files = files

	@classmethod
	def _list_from_string(cls, repo, text):
		"""Create a Stat object from output retrieved by git-diff.
		
		:return: git.Stat"""
		hsh = {'total': {'insertions': 0, 'deletions': 0, 'lines': 0, 'files': 0}, 'files': dict()}
		for line in text.splitlines():
			(raw_insertions, raw_deletions, filename) = line.split("\t")
			insertions = raw_insertions != '-' and int(raw_insertions) or 0
			deletions = raw_deletions != '-' and int(raw_deletions) or 0
			hsh['total']['insertions'] += insertions
			hsh['total']['deletions'] += deletions
			hsh['total']['lines'] += insertions + deletions
			hsh['total']['files'] += 1
			hsh['files'][filename.strip()] = {'insertions': insertions,
											  'deletions': deletions,
											  'lines': insertions + deletions}
		return Stats(hsh['total'], hsh['files'])


class IndexFileSHA1Writer(object):
	"""Wrapper around a file-like object that remembers the SHA1 of 
	the data written to it. It will write a sha when the stream is closed
	or if the asked for explicitly usign write_sha.
	
	Only useful to the indexfile
	
	:note: Based on the dulwich project"""
	__slots__ = ("f", "sha1")
	
	def __init__(self, f):
		self.f = f
		self.sha1 = make_sha("")

	def write(self, data):
		self.sha1.update(data)
		return self.f.write(data)

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
	"""Provides methods to obtain, check for, and release a file based lock which 
	should be used to handle concurrent access to the same file.
	
	As we are a utility class to be derived from, we only use protected methods.
	
	Locks will automatically be released on destruction"""
	__slots__ = ("_file_path", "_owns_lock")
	
	def __init__(self, file_path):
		self._file_path = file_path
		self._owns_lock = False
	
	def __del__(self):
		self._release_lock()
	
	def _lock_file_path(self):
		""":return: Path to lockfile"""
		return "%s.lock" % (self._file_path)
	
	def _has_lock(self):
		""":return: True if we have a lock and if the lockfile still exists
		:raise AssertionError: if our lock-file does not exist"""
		if not self._owns_lock:
			return False
		
		return True
		
	def _obtain_lock_or_raise(self):
		"""Create a lock file as flag for other instances, mark our instance as lock-holder
		
		:raise IOError: if a lock was already present or a lock file could not be written"""
		if self._has_lock():
			return 
		lock_file = self._lock_file_path()
		if os.path.isfile(lock_file):
			raise IOError("Lock for file %r did already exist, delete %r in case the lock is illegal" % (self._file_path, lock_file))
			
		try:
			fd = os.open(lock_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0)
			os.close(fd)
		except OSError,e:
			raise IOError(str(e))
		
		self._owns_lock = True
		
	def _obtain_lock(self):
		"""The default implementation will raise if a lock cannot be obtained.
		Subclasses may override this method to provide a different implementation"""
		return self._obtain_lock_or_raise()
		
	def _release_lock(self):
		"""Release our lock if we have one"""
		if not self._has_lock():
			return
			
		# if someone removed our file beforhand, lets just flag this issue
		# instead of failing, to make it more usable.
		lfp = self._lock_file_path()
		try:
			# on bloody windows, the file needs write permissions to be removable.
			# Why ... 
			if os.name == 'nt':
				os.chmod(lfp, 0777)
			# END handle win32
			os.remove(lfp)
		except OSError:
			pass
		self._owns_lock = False


class BlockingLockFile(LockFile):
	"""The lock file will block until a lock could be obtained, or fail after 
	a specified timeout.
	
	:note: If the directory containing the lock was removed, an exception will 
		be raised during the blocking period, preventing hangs as the lock 
		can never be obtained."""
	__slots__ = ("_check_interval", "_max_block_time")
	def __init__(self, file_path, check_interval_s=0.3, max_block_time_s=sys.maxint):
		"""Configure the instance
		
		:parm check_interval_s:
			Period of time to sleep until the lock is checked the next time.
			By default, it waits a nearly unlimited time
		
		:parm max_block_time_s: Maximum amount of seconds we may lock"""
		super(BlockingLockFile, self).__init__(file_path)
		self._check_interval = check_interval_s
		self._max_block_time = max_block_time_s
		
	def _obtain_lock(self):
		"""This method blocks until it obtained the lock, or raises IOError if 
		it ran out of time or if the parent directory was not available anymore.
		If this method returns, you are guranteed to own the lock"""
		starttime = time.time()
		maxtime = starttime + float(self._max_block_time)
		while True:
			try:
				super(BlockingLockFile, self)._obtain_lock()
			except IOError:
				# synity check: if the directory leading to the lockfile is not
				# readable anymore, raise an execption
				curtime = time.time()
				if not os.path.isdir(os.path.dirname(self._lock_file_path())):
					msg = "Directory containing the lockfile %r was not readable anymore after waiting %g seconds" % (self._lock_file_path(), curtime - starttime)
					raise IOError(msg)
				# END handle missing directory
				
				if curtime >= maxtime:
					msg = "Waited %g seconds for lock at %r" % ( maxtime - starttime, self._lock_file_path())
					raise IOError(msg)
				# END abort if we wait too long
				time.sleep(self._check_interval)
			else:
				break
		# END endless loop
	

class IterableList(list):
	"""
	List of iterable objects allowing to query an object by id or by named index::
	 
	 heads = repo.heads
	 heads.master
	 heads['master']
	 heads[0]
	 
	It requires an id_attribute name to be set which will be queried from its 
	contained items to have a means for comparison.
	
	A prefix can be specified which is to be used in case the id returned by the 
	items always contains a prefix that does not matter to the user, so it 
	can be left out."""
	__slots__ = ('_id_attr', '_prefix')
	
	def __new__(cls, id_attr, prefix=''):
		return super(IterableList,cls).__new__(cls)
		
	def __init__(self, id_attr, prefix=''):
		self._id_attr = id_attr
		self._prefix = prefix
		
	def __getattr__(self, attr):
		attr = self._prefix + attr
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
			raise IndexError( "No item found with id %r" % (self._prefix + index) )


class Iterable(object):
	"""Defines an interface for iterable items which is to assure a uniform 
	way to retrieve and iterate items within the git repository"""
	__slots__ = tuple()
	_id_attribute_ = "attribute that most suitably identifies your instance"
	
	@classmethod
	def list_items(cls, repo, *args, **kwargs):
		"""
		Find all items of this type - subclasses can specify args and kwargs differently.
		If no args are given, subclasses are obliged to return all items if no additional 
		arguments arg given.
		
		:note: Favor the iter_items method as it will
		
		:return:list(Item,...) list of item instances"""
		out_list = IterableList( cls._id_attribute_ )
		out_list.extend(cls.iter_items(repo, *args, **kwargs))
		return out_list
		
		
	@classmethod
	def iter_items(cls, repo, *args, **kwargs):
		"""For more information about the arguments, see list_items
		:return:  iterator yielding Items"""
		raise NotImplementedError("To be implemented by Subclass")
		
		
