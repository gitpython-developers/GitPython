# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Contains basic implementations for the interface building blocks"""
from git.db.interface import *

from git.util import (
		pool,
		join,
		isfile,
		normpath,
		abspath,
		dirname,
		LazyMixin, 
		hex_to_bin,
		bin_to_hex,
		expandvars,
		expanduser,
		exists,
		is_git_dir,
	)

from git.index import IndexFile
from git.config import GitConfigParser
from git.exc import 	(
						BadObject, 
						AmbiguousObjectName,
						InvalidGitRepositoryError,
						NoSuchPathError
						)

from async import ChannelThreadTask

from itertools import chain
import sys
import os


__all__ = (	'PureObjectDBR', 'PureObjectDBW', 'PureRootPathDB', 'PureCompoundDB', 
			'PureConfigurationMixin', 'PureRepositoryPathsMixin', 'PureAlternatesFileMixin',
			'PureIndexDB')
                                                                        

class PureObjectDBR(ObjectDBR):
	
	#{ Query Interface 
		
	def has_object_async(self, reader):
		task = ChannelThreadTask(reader, str(self.has_object_async), lambda sha: (sha, self.has_object(sha)))
		return pool.add_task(task) 
		
	def info_async(self, reader):
		task = ChannelThreadTask(reader, str(self.info_async), self.info)
		return pool.add_task(task)
		
	def stream_async(self, reader):
		# base implementation just uses the stream method repeatedly
		task = ChannelThreadTask(reader, str(self.stream_async), self.stream)
		return pool.add_task(task)
	
	def partial_to_complete_sha_hex(self, partial_hexsha):
		len_partial_hexsha = len(partial_hexsha)
		if len_partial_hexsha % 2 != 0:
			partial_binsha = hex_to_bin(partial_hexsha + "0")
		else:
			partial_binsha = hex_to_bin(partial_hexsha)
		# END assure successful binary conversion
		return self.partial_to_complete_sha(partial_binsha, len(partial_hexsha))
	
	#} END query interface
	
	
class PureObjectDBW(ObjectDBW):
	
	def __init__(self, *args, **kwargs):
		try:
			super(PureObjectDBW, self).__init__(*args, **kwargs)
		except TypeError:
			pass
		#END handle py 2.6 
		self._ostream = None
	
	#{ Edit Interface
	def set_ostream(self, stream):
		cstream = self._ostream
		self._ostream = stream
		return cstream
		
	def ostream(self):
		return self._ostream
	
	def store_async(self, reader):
		task = ChannelThreadTask(reader, str(self.store_async), self.store) 
		return pool.add_task(task)
	
	#} END edit interface
	

class PureRootPathDB(RootPathDB):
	
	def __init__(self, root_path):
		self._root_path = root_path
		super(PureRootPathDB, self).__init__(root_path)
		
		
	#{ Interface 
	def root_path(self):
		return self._root_path
	
	def db_path(self, rela_path=None):
		if not rela_path:
			return self._root_path
		return join(self._root_path, rela_path)
	#} END interface
		

def _databases_recursive(database, output):
	"""Fill output list with database from db, in order. Deals with Loose, Packed 
	and compound databases."""
	if isinstance(database, CompoundDB):
		compounds = list()
		dbs = database.databases()
		output.extend(db for db in dbs if not isinstance(db, CompoundDB))
		for cdb in (db for db in dbs if isinstance(db, CompoundDB)):
			_databases_recursive(cdb, output)
	else:
		output.append(database)
	# END handle database type
	

class PureCompoundDB(CompoundDB, PureObjectDBR, LazyMixin, CachingDB):
	def _set_cache_(self, attr):
		if attr == '_dbs':
			self._dbs = list()
		else:
			super(PureCompoundDB, self)._set_cache_(attr)
	
	#{ PureObjectDBR interface 
	
	def has_object(self, sha):
		for db in self._dbs:
			if db.has_object(sha):
				return True
		#END for each db
		return False
		
	def info(self, sha):
		for db in self._dbs:
			try:
				return db.info(sha)
			except BadObject:
				pass
		#END for each db
		
	def stream(self, sha):
		for db in self._dbs:
			try:
				return db.stream(sha)
			except BadObject:
				pass
		#END for each db

	def size(self):
		return reduce(lambda x,y: x+y, (db.size() for db in self._dbs), 0)
		
	def sha_iter(self):
		return chain(*(db.sha_iter() for db in self._dbs))
		
	#} END object DBR Interface
	
	#{ Interface
	
	def databases(self):
		return tuple(self._dbs)

	def update_cache(self, force=False):
		# something might have changed, clear everything
		stat = False
		for db in self._dbs:
			if isinstance(db, CachingDB):
				stat |= db.update_cache(force)
			# END if is caching db
		# END for each database to update
		return stat
		
	def partial_to_complete_sha_hex(self, partial_hexsha):
		len_partial_hexsha = len(partial_hexsha)
		if len_partial_hexsha % 2 != 0:
			partial_binsha = hex_to_bin(partial_hexsha + "0")
		else:
			partial_binsha = hex_to_bin(partial_hexsha)
		# END assure successful binary conversion 
		
		candidate = None
		for db in self._dbs:
			full_bin_sha = None
			try:
				if hasattr(db, 'partial_to_complete_sha_hex'):
					full_bin_sha = db.partial_to_complete_sha_hex(partial_hexsha)
				else:
					full_bin_sha = db.partial_to_complete_sha(partial_binsha, len_partial_hexsha)
				# END handle database type
			except BadObject:
				continue
			# END ignore bad objects
			if full_bin_sha:
				if candidate and candidate != full_bin_sha:
					raise AmbiguousObjectName(partial_hexsha)
				candidate = full_bin_sha
			# END handle candidate
		# END for each db
		if not candidate:
			raise BadObject(partial_binsha)
		return candidate
		
	def partial_to_complete_sha(self, partial_binsha, hex_len):
		"""Simple adaptor to feed into our implementation"""
		return self.partial_to_complete_sha_hex(bin_to_hex(partial_binsha)[:hex_len])
	#} END interface
	
		
class PureRepositoryPathsMixin(RepositoryPathsMixin):
	# slots has no effect here, its just to keep track of used attrs
	__slots__  = ("_git_path", '_bare', '_working_tree_dir')
	
	#{ Configuration 
	repo_dir = '.git'
	objs_dir = 'objects'
	#} END configuration
	
	#{ Subclass Interface
	def _initialize(self, path):
		epath = abspath(expandvars(expanduser(path or os.getcwd())))

		if not exists(epath):
			raise NoSuchPathError(epath)
		#END check file 

		self._working_tree_dir = None
		self._git_path = None
		curpath = epath
		
		# walk up the path to find the .git dir
		while curpath:
			if is_git_dir(curpath):
				self._git_path = curpath
				self._working_tree_dir = os.path.dirname(curpath)
				break
			gitpath = join(curpath, self.repo_dir)
			if is_git_dir(gitpath):
				self._git_path = gitpath
				self._working_tree_dir = curpath
				break
			curpath, dummy = os.path.split(curpath)
			if not dummy:
				break
		# END while curpath
		
		if self._git_path is None:
			raise InvalidGitRepositoryError(epath)
		# END path not found

		self._bare = self._working_tree_dir is None
		if hasattr(self, 'config_reader'):
			try:
				self._bare = self.config_reader("repository").getboolean('core','bare') 
			except Exception:
				# lets not assume the option exists, although it should
				pass
			#END handle exception
		#END check bare flag
		self._working_tree_dir = self._bare and None or self._working_tree_dir
		
	#} end subclass interface
	
	#{ Object Interface
	
	def __eq__(self, rhs):
		if hasattr(rhs, 'git_dir'):
			return self.git_dir == rhs.git_dir
		return False
		
	def __ne__(self, rhs):
		return not self.__eq__(rhs)
		
	def __hash__(self):
		return hash(self.git_dir)

	def __repr__(self):
		return "%s(%r)" % (type(self).__name__, self.git_dir)
	
	#} END object interface
	
	#{ Interface
	
	@property
	def is_bare(self):
		return self._bare
		
	@property
	def git_dir(self):
		return self._git_path
		
	@property
	def working_tree_dir(self):
		if self._working_tree_dir is None:
			raise AssertionError("Repository at %s is bare and does not have a working tree directory" % self.git_dir)
		#END assertion
		return dirname(self.git_dir)
	
	@property
	def objects_dir(self):
		return join(self.git_dir, self.objs_dir)
	
	@property
	def working_dir(self):
		if self.is_bare:
			return self.git_dir
		else:
			return self.working_tree_dir
		#END handle bare state
		
	def _mk_description():
		def _get_description(self):
			filename = join(self.git_dir, 'description')
			return file(filename).read().rstrip()
	
		def _set_description(self, descr):
			filename = join(self.git_dir, 'description')
			file(filename, 'w').write(descr+'\n')
			
		return property(_get_description, _set_description, "Descriptive text for the content of the repository")

	description = _mk_description()
	del(_mk_description)
	
	#} END interface
		
		
class PureConfigurationMixin(ConfigurationMixin):
	
	#{ Configuration
	system_config_file_name = "gitconfig"
	repo_config_file_name = "config"
	#} END
	
	def __new__(cls, *args, **kwargs):
		"""This is just a stupid workaround for the evil py2.6 change which makes mixins quite impossible"""
		return super(PureConfigurationMixin, cls).__new__(cls, *args, **kwargs)
	
	def __init__(self, *args, **kwargs):
		"""Verify prereqs"""
		try:
			super(PureConfigurationMixin, self).__init__(*args, **kwargs)
		except TypeError:
			pass
		#END handle code-breaking change in python 2.6
		assert hasattr(self, 'git_dir')
	
	def _path_at_level(self, level ):
		# we do not support an absolute path of the gitconfig on windows , 
		# use the global config instead
		if sys.platform == "win32" and level == "system":
			level = "global"
		#END handle windows
			
		if level == "system":
			return "/etc/%s" % self.system_config_file_name
		elif level == "global":
			return normpath(expanduser("~/.%s" % self.system_config_file_name))
		elif level == "repository":
			return join(self.git_dir, self.repo_config_file_name)
		#END handle level
		
		raise ValueError("Invalid configuration level: %r" % level)
		
	#{ Interface
	
	def config_reader(self, config_level=None):
		files = None
		if config_level is None:
			files = [ self._path_at_level(f) for f in self.config_level ]
		else:
			files = [ self._path_at_level(config_level) ]
		#END handle level
		return GitConfigParser(files, read_only=True)
		
	def config_writer(self, config_level="repository"):
		return GitConfigParser(self._path_at_level(config_level), read_only=False)
	
	
	#} END interface
	
	
class PureIndexDB(IndexDB):
	#{ Configuration
	IndexCls = IndexFile
	#} END configuration
	
	@property
	def index(self):
		return self.IndexCls(self)
	
	
class PureAlternatesFileMixin(object):
	"""Utility able to read and write an alternates file through the alternates property
	It needs to be part of a type with the git_dir or db_path property.
	
	The file by default is assumed to be located at the default location as imposed
	by the standard git repository layout"""
	
	#{ Configuration
	alternates_filepath = os.path.join('info', 'alternates')	# relative path to alternates file
	
	#} END configuration
	
	def __init__(self, *args, **kwargs):
		try:
			super(PureAlternatesFileMixin, self).__init__(*args, **kwargs)
		except TypeError:
			pass
		#END handle py2.6 code breaking changes
		self._alternates_path()	# throws on incompatible type
	
	#{ Interface 
	
	def _alternates_path(self):
		if hasattr(self, 'git_dir'):
			return join(self.git_dir, 'objects', self.alternates_filepath)
		elif hasattr(self, 'db_path'):
			return self.db_path(self.alternates_filepath)
		else:
			raise AssertionError("This mixin requires a parent type with either the git_dir property or db_path method")
		#END handle path
	
	def _get_alternates(self):
		"""The list of alternates for this repo from which objects can be retrieved

		:return: list of strings being pathnames of alternates"""
		alternates_path = self._alternates_path()

		if os.path.exists(alternates_path):
			try:
				f = open(alternates_path)
				alts = f.read()
			finally:
				f.close()
			return alts.strip().splitlines()
		else:
			return list()
		# END handle path exists

	def _set_alternates(self, alts):
		"""Sets the alternates

		:parm alts:
			is the array of string paths representing the alternates at which 
			git should look for objects, i.e. /home/user/repo/.git/objects

		:raise NoSuchPathError:
		:note:
			The method does not check for the existance of the paths in alts
			as the caller is responsible."""
		alternates_path = self._alternates_path() 
		if not alts:
			if isfile(alternates_path):
				os.remove(alternates_path)
		else:
			try:
				f = open(alternates_path, 'w')
				f.write("\n".join(alts))
			finally:
				f.close()
			# END file handling 
		# END alts handling

	alternates = property(_get_alternates, _set_alternates, doc="Retrieve a list of alternates paths or set a list paths to be used as alternates")
	
	#} END interface
	
