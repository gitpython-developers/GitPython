# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing module parser implementation able to properly read and write
configuration files
"""

import re
import os
import ConfigParser as cp
from git.odict import OrderedDict
import inspect

class _MetaParserBuilder(type):
	"""
	Utlity class wrapping base-class methods into decorators that assure read-only properties
	"""
	def __new__(metacls, name, bases, clsdict):
		"""
		Equip all base-class methods with a _needs_values decorator, and all non-const methods
		with a _set_dirty_and_flush_changes decorator in addition to that.
		"""
		mutating_methods = clsdict['_mutating_methods_']
		for base in bases:
			methods = ( t for t in inspect.getmembers(base, inspect.ismethod) if not t[0].startswith("_") )
			for name, method in methods:
				if name in clsdict:
					continue
				method_with_values = _needs_values(method)
				if name in mutating_methods:
					method_with_values = _set_dirty_and_flush_changes(method_with_values)
				# END mutating methods handling
				
				clsdict[name] = method_with_values
		# END for each base
		
		new_type = super(_MetaParserBuilder, metacls).__new__(metacls, name, bases, clsdict)
		return new_type
	
	

def _needs_values(func):
	"""
	Returns method assuring we read values (on demand) before we try to access them
	"""
	def assure_data_present(self, *args, **kwargs):
		self.read()
		return func(self, *args, **kwargs)
	# END wrapper method
	assure_data_present.__name__ = func.__name__
	return assure_data_present
	
def _set_dirty_and_flush_changes(non_const_func):
	"""
	Return method that checks whether given non constant function may be called.
	If so, the instance will be set dirty.
	Additionally, we flush the changes right to disk
	"""
	def flush_changes(self, *args, **kwargs):
		rval = non_const_func(self, *args, **kwargs)
		self.write()
		return rval
	# END wrapper method
	flush_changes.__name__ = non_const_func.__name__
	return flush_changes
	
	

class GitConfigParser(cp.RawConfigParser, object):
	"""
	Implements specifics required to read git style configuration files.
	
	This variation behaves much like the git.config command such that the configuration
	will be read on demand based on the filepath given during initialization.
	
	The changes will automatically be written once the instance goes out of scope, but 
	can be triggered manually as well.
	
	The configuration file will be locked if you intend to change values preventing other 
	instances to write concurrently.
	
	NOTE
		The config is case-sensitive even when queried, hence section and option names
		must match perfectly.
	"""
	__metaclass__ = _MetaParserBuilder
	
	OPTCRE = re.compile(
		r'\s?(?P<option>[^:=\s][^:=]*)'		  # very permissive, incuding leading whitespace
		r'\s*(?P<vi>[:=])\s*'				  # any number of space/tab,
											  # followed by separator
											  # (either : or =), followed
											  # by any # space/tab
		r'(?P<value>.*)$'					  # everything up to eol
		)
	
	# list of RawConfigParser methods able to change the instance
	_mutating_methods_ = ("add_section", "remove_section", "remove_option", "set")
	
	def __init__(self, file_or_files, read_only=True):
		"""
		Initialize a configuration reader to read the given file_or_files and to 
		possibly allow changes to it by setting read_only False
		
		``file_or_files``
			A single file path or file objects or multiple of these
		
		``read_only``
			If True, the ConfigParser may only read the data , but not change it.
			If False, only a single file path or file object may be given.
		"""
		# initialize base with ordered dictionaries to be sure we write the same 
		# file back 
		self._sections = OrderedDict()
		self._defaults = OrderedDict()
		
		self._file_or_files = file_or_files
		self._read_only = read_only
		self._owns_lock = False
		self._is_initialized = False
		
		
		if not read_only:
			if isinstance(file_or_files, (tuple, list)):
				raise ValueError("Write-ConfigParsers can operate on a single file only, multiple files have been passed")
			# END single file check
			
			self._file_name = file_or_files
			if not isinstance(self._file_name, basestring):
				self._file_name = file_or_files.name
			# END get filename
			
			self._obtain_lock_or_raise()	
		# END read-only check
		
	
	def __del__(self):
		"""
		Write pending changes if required and release locks
		"""
		# checking for the lock here makes sure we do not raise during write()
		# in case an invalid parser was created who could not get a lock
		if self.read_only or not self._has_lock():
			return
		
		try:
			try:
				self.write()
			except IOError,e:
				print "Exception during destruction of GitConfigParser: %s" % str(e)
		finally:
			self._release_lock()
	
	def _lock_file_path(self):
		"""
		Return
			Path to lockfile
		"""
		return "%s.lock" % (self._file_name)
	
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
			raise IOError("Lock for file %r did already exist, delete %r in case the lock is illegal" % (self._file_name, lock_file))
		
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
		
	def optionxform(self, optionstr):
		"""
		Do not transform options in any way when writing
		"""
		return optionstr
	
	def read(self):
		"""
		Reads the data stored in the files we have been initialized with. It will 
		ignore files that cannot be read, possibly leaving an empty configuration
		
		Returns
			Nothing
		
		Raises
			IOError if a file cannot be handled
		"""
		if self._is_initialized:
			return
			
		
		files_to_read = self._file_or_files
		if not isinstance(files_to_read, (tuple, list)):
			files_to_read = [ files_to_read ]
		
		for file_object in files_to_read:
			fp = file_object
			close_fp = False
			# assume a path if it is not a file-object
			if not hasattr(file_object, "seek"):
				try:
					fp = open(file_object)
				except IOError,e:
					continue
				close_fp = True
			# END fp handling
				
			try:
				self._read(fp, fp.name)
			finally:
				if close_fp:
					fp.close()
			# END read-handling
		# END  for each file object to read
		self._is_initialized = True
		
	def _write(self, fp):
		"""Write an .ini-format representation of the configuration state in 
		git compatible format"""
		def write_section(name, section_dict):
			fp.write("[%s]\n" % name)
			for (key, value) in section_dict.items():
				if key != "__name__":
					fp.write("\t%s = %s\n" % (key, str(value).replace('\n', '\n\t')))
				# END if key is not __name__
		# END section writing 
		
		if self._defaults:
			write_section(cp.DEFAULTSECT, self._defaults)
		map(lambda t: write_section(t[0],t[1]), self._sections.items())

		
	@_needs_values
	def write(self):
		"""
		Write changes to our file, if there are changes at all
		
		Raise
			IOError if this is a read-only writer instance or if we could not obtain 
			a file lock
		"""
		self._assure_writable("write")
		self._obtain_lock_or_raise()
		
		
		fp = self._file_or_files
		close_fp = False
		
		if not hasattr(fp, "seek"):
			fp = open(self._file_or_files, "w")
			close_fp = True
		else:
			fp.seek(0)
		
		# WRITE DATA
		try:
			self._write(fp)
		finally:
			if close_fp:
				fp.close()
		# END data writing
			
		# we do not release the lock - it will be done automatically once the 
		# instance vanishes
		
	def _assure_writable(self, method_name):
		if self.read_only:
			raise IOError("Cannot execute non-constant method %s.%s" % (self, method_name))
		
	@_needs_values
	@_set_dirty_and_flush_changes
	def add_section(self, section):
		"""
		Assures added options will stay in order
		"""
		super(GitConfigParser, self).add_section(section)
		self._sections[section] = OrderedDict()
		
	@property
	def read_only(self):
		"""
		Returns
			True if this instance may change the configuration file
		"""
		return self._read_only
