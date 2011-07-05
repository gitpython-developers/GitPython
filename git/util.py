# utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import platform
import binascii
import os
import mmap
import sys
import errno
import re
import time
import stat
import shutil
import tempfile
from smmap import (
					StaticWindowMapManager,
					SlidingWindowMapManager,
					SlidingWindowMapBuffer
				)



__all__ = ( "stream_copy", "join_path", "to_native_path_windows", "to_native_path_linux", 
			"join_path_native", "Stats", "IndexFileSHA1Writer", "Iterable", "IterableList", 
			"BlockingLockFile", "LockFile", 'Actor', 'get_user_id', 'assure_directory_exists',
			'RepoAliasMixin', 'LockedFD', 'LazyMixin', 'rmtree' )

from cStringIO import StringIO

# in py 2.4, StringIO is only StringI, without write support.
# Hence we must use the python implementation for this
if sys.version_info[1] < 5:
	from StringIO import StringIO
# END handle python 2.4

try:
	import async.mod.zlib as zlib
except ImportError:
	import zlib
# END try async zlib

from async import ThreadPool

try:
    import hashlib
except ImportError:
    import sha

try:
	from struct import unpack_from
except ImportError:
	from struct import unpack, calcsize
	__calcsize_cache = dict()
	def unpack_from(fmt, data, offset=0):
		try:
			size = __calcsize_cache[fmt]
		except KeyError:
			size = calcsize(fmt)
			__calcsize_cache[fmt] = size
		# END exception handling
		return unpack(fmt, data[offset : offset + size])
	# END own unpack_from implementation


#{ Globals

# A pool distributing tasks, initially with zero threads, hence everything 
# will be handled in the main thread
pool = ThreadPool(0)

# initialize our global memory manager instance
# Use it to free cached (and unused) resources.
if sys.version_info[1] < 6:
	mman = StaticWindowMapManager()
else:
	mman = SlidingWindowMapManager()
#END handle mman

#} END globals


#{ Aliases

hex_to_bin = binascii.a2b_hex
bin_to_hex = binascii.b2a_hex

# errors
ENOENT = errno.ENOENT

# os shortcuts
exists = os.path.exists
mkdir = os.mkdir
chmod = os.chmod
isdir = os.path.isdir
isfile = os.path.isfile
rename = os.rename
remove = os.remove
dirname = os.path.dirname
basename = os.path.basename
normpath = os.path.normpath
expandvars = os.path.expandvars
expanduser = os.path.expanduser
abspath = os.path.abspath
join = os.path.join
read = os.read
write = os.write
close = os.close
fsync = os.fsync

# constants
NULL_HEX_SHA = "0"*40
NULL_BIN_SHA = "\0"*20

#} END Aliases

#{ compatibility stuff ... 

class _RandomAccessStringIO(object):
	"""Wrapper to provide required functionality in case memory maps cannot or may 
	not be used. This is only really required in python 2.4"""
	__slots__ = '_sio'
	
	def __init__(self, buf=''):
		self._sio = StringIO(buf)
		
	def __getattr__(self, attr):
		return getattr(self._sio, attr)
	
	def __len__(self):
		return len(self.getvalue())
		
	def __getitem__(self, i):
		return self.getvalue()[i]
		
	def __getslice__(self, start, end):
		return self.getvalue()[start:end]
	
#} END compatibility stuff ...

#{ Routines

def get_user_id():
	""":return: string identifying the currently active system user as name@node
	:note: user can be set with the 'USER' environment variable, usually set on windows"""
	ukn = 'UNKNOWN'
	username = os.environ.get('USER', os.environ.get('USERNAME', ukn))
	if username == ukn and hasattr(os, 'getlogin'):
		username = os.getlogin()
	# END get username from login
	return "%s@%s" % (username, platform.node())

def is_git_dir(d):
	""" This is taken from the git setup.c:is_git_directory
	function."""
	if isdir(d) and \
			isdir(join(d, 'objects')) and \
			isdir(join(d, 'refs')):
		headref = join(d, 'HEAD')
		return isfile(headref) or \
				(os.path.islink(headref) and
				os.readlink(headref).startswith('refs'))
	return False

def rmtree(path):
	"""Remove the given recursively.
	:note: we use shutil rmtree but adjust its behaviour to see whether files that
		couldn't be deleted are read-only. Windows will not remove them in that case"""
	def onerror(func, path, exc_info):
		if not os.access(path, os.W_OK):
			# Is the error an access error ?
			os.chmod(path, stat.S_IWUSR)
			func(path)
		else:
			raise
	# END end onerror
	return shutil.rmtree(path, False, onerror)

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
	
def make_sha(source=''):
    """A python2.4 workaround for the sha/hashlib module fiasco 
    :note: From the dulwich project """
    try:
        return hashlib.sha1(source)
    except NameError:
        sha1 = sha.sha(source)
        return sha1

def allocate_memory(size):
	""":return: a file-protocol accessible memory block of the given size"""
	if size == 0:
		return _RandomAccessStringIO('')
	# END handle empty chunks gracefully
	
	try:
		return mmap.mmap(-1, size)	# read-write by default
	except EnvironmentError:
		# setup real memory instead
		# this of course may fail if the amount of memory is not available in
		# one chunk - would only be the case in python 2.4, being more likely on 
		# 32 bit systems.
		return _RandomAccessStringIO("\0"*size)
	# END handle memory allocation
	

def file_contents_ro(fd, stream=False, allow_mmap=True):
	""":return: read-only contents of the file represented by the file descriptor fd
	:param fd: file descriptor opened for reading
	:param stream: if False, random access is provided, otherwise the stream interface
		is provided.
	:param allow_mmap: if True, its allowed to map the contents into memory, which 
		allows large files to be handled and accessed efficiently. The file-descriptor
		will change its position if this is False"""
	try:
		if allow_mmap:
			# supports stream and random access
			try:
				return mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
			except EnvironmentError:
				# python 2.4 issue, 0 wants to be the actual size
				return mmap.mmap(fd, os.fstat(fd).st_size, access=mmap.ACCESS_READ)
			# END handle python 2.4
	except OSError:
		pass
	# END exception handling
	
	# read manully
	contents = os.read(fd, os.fstat(fd).st_size)
	if stream:
		return _RandomAccessStringIO(contents)
	return contents
	
def file_contents_ro_filepath(filepath, stream=False, allow_mmap=True, flags=0):
	"""Get the file contents at filepath as fast as possible
	:return: random access compatible memory of the given filepath
	:param stream: see ``file_contents_ro``
	:param allow_mmap: see ``file_contents_ro``
	:param flags: additional flags to pass to os.open
	:raise OSError: If the file could not be opened
	:note: for now we don't try to use O_NOATIME directly as the right value needs to be 
		shared per database in fact. It only makes a real difference for loose object 
		databases anyway, and they use it with the help of the ``flags`` parameter"""
	fd = os.open(filepath, os.O_RDONLY|getattr(os, 'O_BINARY', 0)|flags)
	try:
		return file_contents_ro(fd, stream, allow_mmap)
	finally:
		close(fd)
	# END assure file is closed
	
def to_hex_sha(sha):
	""":return: hexified version  of sha"""
	if len(sha) == 40:
		return sha
	return bin_to_hex(sha)
	
def to_bin_sha(sha):
	if len(sha) == 20:
		return sha
	return hex_to_bin(sha)

def join_path(a, *p):
	"""Join path tokens together similar to os.path.join, but always use 
	'/' instead of possibly '\' on windows."""
	path = a
	for b in p:
		if len(b) == 0:
			continue
		if b.startswith('/'):
			path += b[1:]
		elif path == '' or path.endswith('/'):
			path +=	 b
		else:
			path += '/' + b
	# END for each path token to add
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
	"""
	As join path, but makes sure an OS native path is returned. This is only 
		needed to play it safe on my dear windows and to assure nice paths that only 
		use '\'"""
	return to_native_path(join_path(a, *p))

def assure_directory_exists(path, is_file=False):
	"""Assure that the directory pointed to by path exists.
	
	:param is_file: If True, path is assumed to be a file and handled correctly.
		Otherwise it must be a directory
	:return: True if the directory was created, False if it already existed"""
	if is_file:
		path = os.path.dirname(path)
	#END handle file 
	if not os.path.isdir(path):
		os.makedirs(path)
		return True
	return False


#} END routines


#{ Utilities

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
		returned from our dict/slots. """
		self._set_cache_(attr)
		# will raise in case the cache was not created
		return object.__getattribute__(self, attr)

	def _set_cache_(self, attr):
		"""
		This method should be overridden in the derived class. 
		It should check whether the attribute named by attr can be created
		and cached. Do nothing if you do not know the attribute or call your subclass
		
		The derived class may create as many additional attributes as it deems 
		necessary in case a git command returns more information than represented 
		in the single attribute."""
		pass

	
class LockedFD(object):
	"""
	This class facilitates a safe read and write operation to a file on disk.
	If we write to 'file', we obtain a lock file at 'file.lock' and write to 
	that instead. If we succeed, the lock file will be renamed to overwrite 
	the original file.
	
	When reading, we obtain a lock file, but to prevent other writers from 
	succeeding while we are reading the file.
	
	This type handles error correctly in that it will assure a consistent state 
	on destruction.
	
	:note: with this setup, parallel reading is not possible"""
	__slots__ = ("_filepath", '_fd', '_write')
	
	def __init__(self, filepath):
		"""Initialize an instance with the givne filepath"""
		self._filepath = filepath
		self._fd = None
		self._write = None			# if True, we write a file
	
	def __del__(self):
		# will do nothing if the file descriptor is already closed
		if self._fd is not None:
			self.rollback()
		
	def _lockfilepath(self):
		return "%s.lock" % self._filepath
		
	def open(self, write=False, stream=False):
		"""
		Open the file descriptor for reading or writing, both in binary mode.
		
		:param write: if True, the file descriptor will be opened for writing. Other
			wise it will be opened read-only.
		:param stream: if True, the file descriptor will be wrapped into a simple stream 
			object which supports only reading or writing
		:return: fd to read from or write to. It is still maintained by this instance
			and must not be closed directly
		:raise IOError: if the lock could not be retrieved
		:raise OSError: If the actual file could not be opened for reading
		:note: must only be called once"""
		if self._write is not None:
			raise AssertionError("Called %s multiple times" % self.open)
		
		self._write = write
		
		# try to open the lock file
		binary = getattr(os, 'O_BINARY', 0)
		lockmode = 	os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary
		try:
			fd = os.open(self._lockfilepath(), lockmode, 0600)
			if not write:
				os.close(fd)
			else:
				self._fd = fd
			# END handle file descriptor
		except OSError:
			raise IOError("Lock at %r could not be obtained" % self._lockfilepath())
		# END handle lock retrieval
		
		# open actual file if required
		if self._fd is None:
			# we could specify exlusive here, as we obtained the lock anyway
			try:
				self._fd = os.open(self._filepath, os.O_RDONLY | binary)
			except:
				# assure we release our lockfile
				os.remove(self._lockfilepath())
				raise
			# END handle lockfile
		# END open descriptor for reading
		
		if stream:
			# need delayed import
			from stream import FDStream
			return FDStream(self._fd)
		else:
			return self._fd
		# END handle stream
		
	def commit(self):
		"""When done writing, call this function to commit your changes into the 
		actual file. 
		The file descriptor will be closed, and the lockfile handled.
		:note: can be called multiple times"""
		self._end_writing(successful=True)
		
	def rollback(self):
		"""Abort your operation without any changes. The file descriptor will be 
		closed, and the lock released.
		:note: can be called multiple times"""
		self._end_writing(successful=False)
		
	def _end_writing(self, successful=True):
		"""Handle the lock according to the write mode """
		if self._write is None:
			raise AssertionError("Cannot end operation if it wasn't started yet")
		
		if self._fd is None:
			return
		
		os.close(self._fd)
		self._fd = None
		
		lockfile = self._lockfilepath()
		if self._write and successful:
			# on windows, rename does not silently overwrite the existing one
			if sys.platform == "win32":
				if isfile(self._filepath):
					os.remove(self._filepath)
				# END remove if exists
			# END win32 special handling
			os.rename(lockfile, self._filepath)
			
			# assure others can at least read the file - the tmpfile left it at rw--
			# We may also write that file, on windows that boils down to a remove-
			# protection as well
			chmod(self._filepath, 0644)
		else:
			# just delete the file so far, we failed
			os.remove(lockfile)
		# END successful handling
		
		
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


class Actor(object):
	"""Actors hold information about a person acting on the repository. They 
	can be committers and authors or anything with a name and an email as 
	mentioned in the git log entries."""
	# PRECOMPILED REGEX
	name_only_regex = re.compile( r'<(.+)>' )
	name_email_regex = re.compile( r'(.*) <(.+?)>' )
	
	# ENVIRONMENT VARIABLES
	# read when creating new commits
	env_author_name = "GIT_AUTHOR_NAME"
	env_author_email = "GIT_AUTHOR_EMAIL"
	env_committer_name = "GIT_COMMITTER_NAME"
	env_committer_email = "GIT_COMMITTER_EMAIL"
	
	# CONFIGURATION KEYS
	conf_name = 'name'
	conf_email = 'email'
	
	__slots__ = ('name', 'email')
	
	def __init__(self, name, email):
		self.name = name
		self.email = email

	def __eq__(self, other):
		return self.name == other.name and self.email == other.email
		
	def __ne__(self, other):
		return not (self == other)
		
	def __hash__(self):
		return hash((self.name, self.email))

	def __str__(self):
		return self.name

	def __repr__(self):
		return '<git.Actor "%s <%s>">' % (self.name, self.email)

	@classmethod
	def _from_string(cls, string):
		"""Create an Actor from a string.
		:param string: is the string, which is expected to be in regular git format

				John Doe <jdoe@example.com>
				
		:return: Actor """
		m = cls.name_email_regex.search(string)
		if m:
			name, email = m.groups()
			return cls(name, email)
		else:
			m = cls.name_only_regex.search(string)
			if m:
				return cls(m.group(1), None)
			else:
				# assume best and use the whole string as name
				return cls(string, None)
			# END special case name
		# END handle name/email matching
		
	@classmethod
	def _main_actor(cls, env_name, env_email, config_reader=None):
		actor = cls('', '')
		default_email = get_user_id()
		default_name = default_email.split('@')[0]
		
		for attr, evar, cvar, default in (('name', env_name, cls.conf_name, default_name), 
										('email', env_email, cls.conf_email, default_email)):
			try:
				setattr(actor, attr, os.environ[evar])
			except KeyError:
				if config_reader is not None:
					setattr(actor, attr, config_reader.get_value('user', cvar, default))
				#END config-reader handling
				if not getattr(actor, attr):
					setattr(actor, attr, default)
			#END handle name
		#END for each item to retrieve
		return actor
		
		
	@classmethod
	def committer(cls, config_reader=None):
		"""
		:return: Actor instance corresponding to the configured committer. It behaves
			similar to the git implementation, such that the environment will override 
			configuration values of config_reader. If no value is set at all, it will be
			generated
		:param config_reader: ConfigReader to use to retrieve the values from in case
			they are not set in the environment"""
		return cls._main_actor(cls.env_committer_name, cls.env_committer_email, config_reader)
		
	@classmethod
	def author(cls, config_reader=None):
		"""Same as committer(), but defines the main author. It may be specified in the environment, 
		but defaults to the committer"""
		return cls._main_actor(cls.env_author_name, cls.env_author_email, config_reader)
		

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
		if not isinstance(id_attr, basestring):
			raise ValueError("First parameter must be a string identifying the name-property. Extend the list after initialization")
		# END help debugging !
		
	def __contains__(self, attr):
		# first try identy match for performance
		rval = list.__contains__(self, attr)
		if rval:
			return rval
		#END handle match
		
		# otherwise make a full name search
		try:
			getattr(self, attr)
			return True
		except (AttributeError, TypeError):
			return False
		#END handle membership
		
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
		# END handle getattr
			
	def __delitem__(self, index):
		delindex = index
		if not isinstance(index, int):
			delindex = -1
			name = self._prefix + index
			for i, item in enumerate(self):
				if getattr(item, self._id_attr) == name:
					delindex = i
					break
				#END search index
			#END for each item
			if delindex == -1:
				raise IndexError("Item with name %s not found" % name)
			#END handle error
		#END get index to delete
		list.__delitem__(self, delindex)


#} END utilities

#{ Classes

class RepoAliasMixin(object):
	"""Simple utility providing a repo-property which resolves to the 'odb' attribute
	of the actual type. This is for api compatability only, as the types previously
	held repository instances, now they hold odb instances instead"""
	__slots__ = tuple()
	
	@property
	def repo(self):
		return self.odb
	

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


#} END classes
