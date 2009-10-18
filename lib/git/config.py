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
from ConfigParser import RawConfigParser

class _MetaParserBuilder(type):
	"""
	Utlity class wrapping methods into decorators that assure read-only properties
	"""

def _needs_values(func):
	"""Returns method assuring we read values (on demand) before we try to access them"""
	return func
	
def _ensure_writable(non_const_func):
	"""Return method that checks whether given non constant function may be called.
	If so, the instance will be set dirty"""
	
	

class GitConfigParser(RawConfigParser, object):
	"""
	Implements specifics required to read git style configuration files.
	
	This variation behaves much like the git.config command such that the configuration
	will be read on demand based on the filepath given during initialization.
	
	The changes will automatically be written once the instance goes out of scope, but 
	can be triggered manually as well.
	
	The configuration file will be locked if you intend to change values preventing other 
	instances to write concurrently.
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
	_mutating_methods_ = tuple()	
	
	
	def __init__(self, file_or_files, read_only=True):
		"""
		Initialize a configuration reader to read the given file_or_files and to 
		possibly allow changes to it by setting read_only False 
		"""
		self._file_or_files = file_or_files
		self._read_only = read_only
		self._is_initialized = False
		self._is_dirty = False
	
	def __del__(self):
		"""
		Write pending changes if required and release locks
		"""
	
	def read(self):
		"""
		Read configuration information from our file or files
		"""
		if self._is_initialized:
			return 
		
		self._is_initialized = True
		
	@_ensure_writable
	def write(self):
		"""
		Write our changes to our file
		
		Raise
			AssertionError if this is a read-only writer instance
		"""
		if not self._is_dirty:
			return
		
		self._is_dirty = False
		
	@property
	def read_only(self):
		"""
		Returns
			True if this instance may change the configuration file
		"""
		return self._read_only
