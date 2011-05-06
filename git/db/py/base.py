# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Contains basic implementations for the interface building blocks"""
from git.db.interface import *

from git.util import (
		pool,
		join,
		normpath,
		abspath,
		dirname,
		LazyMixin, 
		hex_to_bin,
		bin_to_hex,
		expandvars,
		expanduser,
		exists,
		is_git_dir
	)

from git.config import GitConfigParser
from git.exc import 	(
						BadObject, 
						AmbiguousObjectName,
						InvalidDBRoot
						)

from async import ChannelThreadTask

from itertools import chain
import sys
import os


__all__ = (	'PureObjectDBR', 'PureObjectDBW', 'PureRootPathDB', 'PureCompoundDB', 
			'PureConfigurationMixin', 'PureRepositoryPathsMixin')


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
		super(PureObjectDBW, self).__init__(*args, **kwargs)
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
		super(PureRootPathDB, self).__init__(root_path)
		self._root_path = root_path
		
		
	#{ Interface 
	def root_path(self):
		return self._root_path
	
	def db_path(self, rela_path):
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
		elif attr == '_db_cache':
			self._db_cache = dict()
		else:
			super(PureCompoundDB, self)._set_cache_(attr)
	
	def _db_query(self, sha):
		""":return: database containing the given 20 byte sha
		:raise BadObject:"""
		# most databases use binary representations, prevent converting 
		# it everytime a database is being queried
		try:
			return self._db_cache[sha]
		except KeyError:
			pass
		# END first level cache
		
		for db in self._dbs:
			if db.has_object(sha):
				self._db_cache[sha] = db
				return db
		# END for each database
		raise BadObject(sha)
	
	#{ PureObjectDBR interface 
	
	def has_object(self, sha):
		try:
			self._db_query(sha)
			return True
		except BadObject:
			return False
		# END handle exceptions
		
	def info(self, sha):
		return self._db_query(sha).info(sha)
		
	def stream(self, sha):
		return self._db_query(sha).stream(sha)

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
		self._db_cache.clear()
		stat = False
		for db in self._dbs:
			if isinstance(db, CachingDB):
				stat |= db.update_cache(force)
			# END if is caching db
		# END for each database to update
		return stat
		
	def partial_to_complete_sha_hex(self, partial_hexsha):
		databases = self.databases()
		
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
	__slots__  = ("_git_path", '_bare')
	
	#{ Configuration 
	repo_dir = '.git'
	objs_dir = 'objects'
	#} END configuration
	
	#{ Subclass Interface
	def _initialize(self, path):
		epath = abspath(expandvars(expanduser(path or os.getcwd())))

		if not exists(epath):
			raise InvalidDBRoot(epath)
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
			raise InvalidDBRoot(epath)
		# END path not found

		self._bare = self._git_path.endswith(self.repo_dir)
		if hasattr(self, 'config_reader'):
			try:
				self._bare = self.config_reader("repository").getboolean('core','bare') 
			except Exception:
				# lets not assume the option exists, although it should
				pass
		#END check bare flag

	
	#} end subclass interface
	
	#{ Interface
	
	def is_bare(self):
		return self._bare
		
	def git_path(self):
		return self._git_path
		
	def working_tree_path(self):
		if self.is_bare():
			raise AssertionError("Repository at %s is bare and does not have a working tree directory" % self.git_path())
		#END assertion
		return dirname(self.git_path())
		
	def objects_path(self):
		return join(self.git_path(), self.objs_dir)
		
	def working_dir(self):
		if self.is_bare():
			return self.git_path()
		else:
			return self.working_tree_dir()
		#END handle bare state
		
	#} END interface
		
		
class PureConfigurationMixin(ConfigurationMixin):
	
	#{ Configuration
	system_config_file_name = "gitconfig"
	repo_config_file_name = "config"
	#} END
	
	def __init__(self, *args, **kwargs):
		"""Verify prereqs"""
		assert hasattr(self, 'git_path')
	
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
			return join(self.git_path(), self.repo_config_file_name)
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
	
