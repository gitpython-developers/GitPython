# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module containing module parser implementation able to properly read and write
configuration files"""

import re
import os
import ConfigParser as cp
import inspect
import cStringIO

from git.odict import OrderedDict
from git.util import LockFile

__all__ = ('GitConfigParser', 'SectionConstraint')

class MetaParserBuilder(type):
	"""Utlity class wrapping base-class methods into decorators that assure read-only properties"""
	def __new__(metacls, name, bases, clsdict):
		"""
		Equip all base-class methods with a needs_values decorator, and all non-const methods
		with a set_dirty_and_flush_changes decorator in addition to that."""
		kmm = '_mutating_methods_'
		if kmm in clsdict:
			mutating_methods = clsdict[kmm]
			for base in bases:
				methods = ( t for t in inspect.getmembers(base, inspect.ismethod) if not t[0].startswith("_") )
				for name, method in methods:
					if name in clsdict:
						continue
					method_with_values = needs_values(method)
					if name in mutating_methods:
						method_with_values = set_dirty_and_flush_changes(method_with_values)
					# END mutating methods handling
					
					clsdict[name] = method_with_values
				# END for each name/method pair
			# END for each base
		# END if mutating methods configuration is set
		
		new_type = super(MetaParserBuilder, metacls).__new__(metacls, name, bases, clsdict)
		return new_type
	
	

def needs_values(func):
	"""Returns method assuring we read values (on demand) before we try to access them"""
	def assure_data_present(self, *args, **kwargs):
		self.read()
		return func(self, *args, **kwargs)
	# END wrapper method
	assure_data_present.__name__ = func.__name__
	return assure_data_present
	
def set_dirty_and_flush_changes(non_const_func):
	"""Return method that checks whether given non constant function may be called.
	If so, the instance will be set dirty.
	Additionally, we flush the changes right to disk"""
	def flush_changes(self, *args, **kwargs):
		rval = non_const_func(self, *args, **kwargs)
		self.write()
		return rval
	# END wrapper method
	flush_changes.__name__ = non_const_func.__name__
	return flush_changes
	

class SectionConstraint(object):
	"""Constrains a ConfigParser to only option commands which are constrained to 
	always use the section we have been initialized with.
	
	It supports all ConfigParser methods that operate on an option"""
	__slots__ = ("_config", "_section_name")
	_valid_attrs_ = ("get_value", "set_value", "get", "set", "getint", "getfloat", "getboolean", "has_option", 
					"remove_section", "remove_option", "options")
	
	def __init__(self, config, section):
		self._config = config
		self._section_name = section
		
	def __getattr__(self, attr):
		if attr in self._valid_attrs_:
			return lambda *args, **kwargs: self._call_config(attr, *args, **kwargs)
		return super(SectionConstraint,self).__getattribute__(attr)
		
	def _call_config(self, method, *args, **kwargs):
		"""Call the configuration at the given method which must take a section name 
		as first argument"""
		return getattr(self._config, method)(self._section_name, *args, **kwargs)
		
	@property
	def config(self):
		"""return: Configparser instance we constrain"""
		return self._config
		

class GitConfigParser(cp.RawConfigParser, object):
	"""Implements specifics required to read git style configuration files.
	
	This variation behaves much like the git.config command such that the configuration
	will be read on demand based on the filepath given during initialization.
	
	The changes will automatically be written once the instance goes out of scope, but 
	can be triggered manually as well.
	
	The configuration file will be locked if you intend to change values preventing other 
	instances to write concurrently.
	
	:note:
		The config is case-sensitive even when queried, hence section and option names
		must match perfectly."""
	__metaclass__ = MetaParserBuilder
	
	
	#{ Configuration
	# The lock type determines the type of lock to use in new configuration readers.
	# They must be compatible to the LockFile interface.
	# A suitable alternative would be the BlockingLockFile
	t_lock = LockFile
	re_comment = re.compile('^\s*[#;]')
	
	#} END configuration 
	
	OPTCRE = re.compile(
		r'\s*(?P<option>[^:=\s][^:=]*)'		  # very permissive, incuding leading whitespace
		r'\s*(?P<vi>[:=])\s*'				  # any number of space/tab,
											  # followed by separator
											  # (either : or =), followed
											  # by any # space/tab
		r'(?P<value>.*)$'					  # everything up to eol
		)
	
	# list of RawConfigParser methods able to change the instance
	_mutating_methods_ = ("add_section", "remove_section", "remove_option", "set")
	__slots__ = ("_sections", "_defaults", "_file_or_files", "_read_only","_is_initialized", '_lock')
	
	def __init__(self, file_or_files, read_only=True):
		"""Initialize a configuration reader to read the given file_or_files and to 
		possibly allow changes to it by setting read_only False
		
		:param file_or_files:
			A single file path or file objects or multiple of these
		
		:param read_only:
			If True, the ConfigParser may only read the data , but not change it.
			If False, only a single file path or file object may be given."""
		super(GitConfigParser, self).__init__()
		# initialize base with ordered dictionaries to be sure we write the same 
		# file back 
		self._sections = OrderedDict()
		self._defaults = OrderedDict()
		
		self._file_or_files = file_or_files
		self._read_only = read_only
		self._is_initialized = False
		self._lock = None
		
		if not read_only:
			if isinstance(file_or_files, (tuple, list)):
				raise ValueError("Write-ConfigParsers can operate on a single file only, multiple files have been passed")
			# END single file check
			
			if not isinstance(file_or_files, basestring):
				file_or_files = file_or_files.name
			# END get filename from handle/stream
			# initialize lock base - we want to write
			self._lock = self.t_lock(file_or_files)
			
			self._lock._obtain_lock()
		# END read-only check
		
	
	def __del__(self):
		"""Write pending changes if required and release locks"""
		# checking for the lock here makes sure we do not raise during write()
		# in case an invalid parser was created who could not get a lock
		if self.read_only or not self._lock._has_lock():
			return
		
		try:
			try:
				self.write()
			except IOError,e:
				print "Exception during destruction of GitConfigParser: %s" % str(e)
		finally:
			self._lock._release_lock()
	
	def optionxform(self, optionstr):
		"""Do not transform options in any way when writing"""
		return optionstr
	
	def _read(self, fp, fpname):
		"""A direct copy of the py2.4 version of the super class's _read method
		to assure it uses ordered dicts. Had to change one line to make it work.
		
		Future versions have this fixed, but in fact its quite embarassing for the 
		guys not to have done it right in the first place !
		
		Removed big comments to make it more compact.
		
		Made sure it ignores initial whitespace as git uses tabs"""
		cursect = None							  # None, or a dictionary
		optname = None
		lineno = 0
		e = None								  # None, or an exception
		while True:
			line = fp.readline()
			if not line:
				break
			lineno = lineno + 1
			# comment or blank line?
			if line.strip() == '' or self.re_comment.match(line):
				continue
			if line.split(None, 1)[0].lower() == 'rem' and line[0] in "rR":
				# no leading whitespace
				continue
			else:
				# is it a section header?
				mo = self.SECTCRE.match(line.strip())
				if mo:
					sectname = mo.group('header').strip()
					if sectname in self._sections:
						cursect = self._sections[sectname]
					elif sectname == cp.DEFAULTSECT:
						cursect = self._defaults
					else:
						# THE ONLY LINE WE CHANGED !
						cursect = OrderedDict((('__name__', sectname),))
						self._sections[sectname] = cursect
					# So sections can't start with a continuation line
					optname = None
				# no section header in the file?
				elif cursect is None:
					raise cp.MissingSectionHeaderError(fpname, lineno, line)
				# an option line?
				else:
					mo = self.OPTCRE.match(line)
					if mo:
						optname, vi, optval = mo.group('option', 'vi', 'value')
						if vi in ('=', ':') and ';' in optval:
							pos = optval.find(';')
							if pos != -1 and optval[pos-1].isspace():
								optval = optval[:pos]
						optval = optval.strip()
						if optval == '""':
							optval = ''
						optname = self.optionxform(optname.rstrip())
						cursect[optname] = optval
					else:
						if not e:
							e = cp.ParsingError(fpname)
						e.append(lineno, repr(line))
					# END  
				# END ? 
			# END ?
		# END while reading 
		# if any parsing errors occurred, raise an exception
		if e:
			raise e
	
	
	def read(self):
		"""Reads the data stored in the files we have been initialized with. It will 
		ignore files that cannot be read, possibly leaving an empty configuration
		
		:return: Nothing
		:raise IOError: if a file cannot be handled"""
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
					close_fp = True
				except IOError,e:
					continue
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

		
	@needs_values
	def write(self):
		"""Write changes to our file, if there are changes at all
		
		:raise IOError: if this is a read-only writer instance or if we could not obtain 
			a file lock"""
		self._assure_writable("write")
		
		fp = self._file_or_files
		close_fp = False
		
		# we have a physical file on disk, so get a lock
		if isinstance(fp, (basestring, file)):
			self._lock._obtain_lock()
		# END get lock for physical files
		
		if not hasattr(fp, "seek"):
			fp = open(self._file_or_files, "w")
			close_fp = True
		else:
			fp.seek(0)
			# make sure we do not overwrite into an existing file
			if hasattr(fp, 'truncate'):
				fp.truncate()
			#END 
		# END handle stream or file
		
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
		
	@needs_values
	@set_dirty_and_flush_changes
	def add_section(self, section):
		"""Assures added options will stay in order"""
		super(GitConfigParser, self).add_section(section)
		self._sections[section] = OrderedDict()
		
	@property
	def read_only(self):
		""":return: True if this instance may change the configuration file"""
		return self._read_only
		
	def get_value(self, section, option, default = None):
		"""
		:param default:
			If not None, the given default value will be returned in case 
			the option did not exist
		:return: a properly typed value, either int, float or string
		
		:raise TypeError: in case the value could not be understood
			Otherwise the exceptions known to the ConfigParser will be raised."""
		try:
			valuestr = self.get(section, option)
		except Exception:
			if default is not None:
				return default
			raise
		
		types = ( long, float )
		for numtype in types:
			try:
				val = numtype( valuestr )

				# truncated value ?
				if val != float( valuestr ):
					continue

				return val
			except (ValueError,TypeError):
				continue
		# END for each numeric type
		
		# try boolean values as git uses them
		vl = valuestr.lower() 
		if vl == 'false':
			return False
		if vl == 'true':
			return True
		
		if not isinstance( valuestr, basestring ):
			raise TypeError( "Invalid value type: only int, long, float and str are allowed", valuestr )
		
		return valuestr
	
	@needs_values
	@set_dirty_and_flush_changes
	def set_value(self, section, option, value):
		"""Sets the given option in section to the given value.
		It will create the section if required, and will not throw as opposed to the default 
		ConfigParser 'set' method.
		
		:param section: Name of the section in which the option resides or should reside
		:param option: Name of the options whose value to set
			
		:param value: Value to set the option to. It must be a string or convertible 
			to a string"""
		if not self.has_section(section):
			self.add_section(section)
		self.set(section, option, str(value))
