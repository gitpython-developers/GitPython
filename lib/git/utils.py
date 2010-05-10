# utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import sys
import time
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

def join_path(a, *p):
    """Join path tokens together similar to os.path.join, but always use 
    '/' instead of possibly '\' on windows."""
    path = a
    for b in p:
        if b.startswith('/'):
            path += b[1:]
        elif path == '' or path.endswith('/'):
            path +=  b
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
        if os.path.isfile(lock_file):
            raise IOError("Lock for file %r did already exist, delete %r in case the lock is illegal" % (self._file_path, lock_file))
            
        try:
            fd = os.open(lock_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0)
            os.close(fd)
        except OSError,e:
            raise IOError(str(e))
        
        self._owns_lock = True
        
    def _obtain_lock(self):
        """
        The default implementation will raise if a lock cannot be obtained.
        Subclasses may override this method to provide a different implementation
        """
        return self._obtain_lock_or_raise()
        
    def _release_lock(self):
        """
        Release our lock if we have one
        """
        if not self._has_lock():
            return
            
        # if someone removed our file beforhand, lets just flag this issue
        # instead of failing, to make it more usable.
        lfp = self._lock_file_path()
        if os.path.isfile(lfp):
            os.remove(lfp)
        self._owns_lock = False


class BlockingLockFile(LockFile):
    """The lock file will block until a lock could be obtained, or fail after 
    a specified timeout"""
    __slots__ = ("_check_interval", "_max_block_time")
    def __init__(self, file_path, check_interval_s=0.3, max_block_time_s=sys.maxint):
        """Configure the instance
        
        ``check_interval_s``
            Period of time to sleep until the lock is checked the next time.
            By default, it waits a nearly unlimited time
        
        ``max_block_time_s``
            Maximum amount of seconds we may lock
        """
        super(BlockingLockFile, self).__init__(file_path)
        self._check_interval = check_interval_s
        self._max_block_time = max_block_time_s
        
    def _obtain_lock(self):
        """This method blocks until it obtained the lock, or raises IOError if 
        it ran out of time.
        If this method returns, you are guranteed to own the lock"""
        starttime = time.time()
        maxtime = starttime + float(self._max_block_time)
        while True:
            try:
                super(BlockingLockFile, self)._obtain_lock()
            except IOError:
                curtime = time.time()
                if curtime >= maxtime:
                    msg = "Waited %f seconds for lock at %r" % ( maxtime - starttime, self._lock_file_path())
                    raise IOError(msg)
                # END abort if we wait too long
                time.sleep(self._check_interval)
            else:
                break
        # END endless loop
    
    
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
        self._temp_write_fp = open(tempfile.mktemp(basename, '', dirname), "wb")
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
            
        if not self._temp_write_fp.closed:
            self._temp_write_fp.close()
        
        if successful:
            # on windows, rename does not silently overwrite the existing one
            if sys.platform == "win32":
                if os.path.isfile(self._file_path):
                    os.remove(self._file_path)
                # END remove if exists
            # END win32 special handling
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
     
    It requires an id_attribute name to be set which will be queried from its 
    contained items to have a means for comparison.
    
    A prefix can be specified which is to be used in case the id returned by the 
    items always contains a prefix that does not matter to the user, so it 
    can be left out.
    """
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
        
        
