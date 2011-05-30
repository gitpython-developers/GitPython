# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of PureCompatibilityGitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Utilities used in ODB testing"""
from git.base import OStream
from git.stream import ( 
							Sha1Writer, 
							ZippedStoreShaWriter
						)

from git.util import (
						zlib,
						dirname
					)

import sys
import random
from array import array
from cStringIO import StringIO

import glob
import unittest
import tempfile
import shutil
import os
import gc


#{ Decorators

def with_rw_directory(func):
	"""Create a temporary directory which can be written to, remove it if the 
	test suceeds, but leave it otherwise to aid additional debugging"""
	def wrapper(self):
		path = maketemp(prefix=func.__name__)
		os.mkdir(path)
		keep = False
		try:
			try:
				return func(self, path)
			except Exception:
				print >> sys.stderr, "Test %s.%s failed, output is at %r" % (type(self).__name__, func.__name__, path)
				keep = True
				raise
		finally:
			# Need to collect here to be sure all handles have been closed. It appears
			# a windows-only issue. In fact things should be deleted, as well as 
			# memory maps closed, once objects go out of scope. For some reason
			# though this is not the case here unless we collect explicitly.
			if not keep:
				gc.collect()
				shutil.rmtree(path)
		# END handle exception
	# END wrapper
	
	wrapper.__name__ = func.__name__
	return wrapper


def with_rw_repo(func):
	"""Create a copy of our repository and put it into a writable location. It will 
	be removed if the test doesn't result in an error.
	As we can currently only copy the fully working tree, tests must not rely on 
	being on a certain branch or on anything really except for the default tags
	that should exist
	Wrapped function obtains a git repository """
	def wrapper(self, path):
		src_dir = dirname(dirname(dirname(__file__)))
		assert(os.path.isdir(path))
		os.rmdir(path)		# created by wrapper, but must not exist for copy operation
		shutil.copytree(src_dir, path)
		target_gitdir = os.path.join(path, '.git')
		assert os.path.isdir(target_gitdir)
		return func(self, self.RepoCls(target_gitdir))
	#END wrapper
	wrapper.__name__ = func.__name__
	return with_rw_directory(wrapper)
	


def with_packs_rw(func):
	"""Function that provides a path into which the packs for testing should be 
	copied. Will pass on the path to the actual function afterwards
	
	:note: needs with_rw_directory wrapped around it"""
	def wrapper(self, path):
		src_pack_glob = fixture_path('packs/*')
		print src_pack_glob
		copy_files_globbed(src_pack_glob, path, hard_link_ok=True)
		return func(self, path)
	# END wrapper
	
	wrapper.__name__ = func.__name__
	return with_rw_directory(wrapper)

#} END decorators

#{ Routines

def rorepo_dir():
	""":return: path to our own repository, being our own .git directory.
	:note: doesn't work in bare repositories"""
	base = os.path.join(dirname(dirname(dirname(dirname(__file__)))), '.git')
	assert os.path.isdir(base)
	return base

def maketemp(*args, **kwargs):
	"""Wrapper around default tempfile.mktemp to fix an osx issue"""
	tdir = tempfile.mktemp(*args, **kwargs)
	if sys.platform == 'darwin':
		tdir = '/private' + tdir
	return tdir

def fixture_path(relapath=''):
	""":return: absolute path into the fixture directory
	:param relapath: relative path into the fixtures directory, or ''
		to obtain the fixture directory itself"""
	test_dir = os.path.dirname(os.path.dirname(__file__))
	return os.path.join(test_dir, "fixtures", relapath)
	
def fixture(name):
	return open(fixture_path(name), 'rb').read()

def absolute_project_path():
	return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def copy_files_globbed(source_glob, target_dir, hard_link_ok=False):
	"""Copy all files found according to the given source glob into the target directory
	:param hard_link_ok: if True, hard links will be created if possible. Otherwise 
		the files will be copied"""
	for src_file in glob.glob(source_glob):
		if hard_link_ok and hasattr(os, 'link'):
			target = os.path.join(target_dir, os.path.basename(src_file))
			try:
				os.link(src_file, target)
			except OSError:
				shutil.copy(src_file, target_dir)
			# END handle cross device links ( and resulting failure )
		else:
			shutil.copy(src_file, target_dir)
		# END try hard link
	# END for each file to copy
	

def make_bytes(size_in_bytes, randomize=False):
	""":return: string with given size in bytes
	:param randomize: try to produce a very random stream"""
	actual_size = size_in_bytes / 4
	producer = xrange(actual_size)
	if randomize:
		producer = list(producer)
		random.shuffle(producer)
	# END randomize
	a = array('i', producer)
	return a.tostring()

def make_object(type, data):
	""":return: bytes resembling an uncompressed object"""
	odata = "blob %i\0" % len(data)
	return odata + data
	
def make_memory_file(size_in_bytes, randomize=False):
	""":return: tuple(size_of_stream, stream)
	:param randomize: try to produce a very random stream"""
	d = make_bytes(size_in_bytes, randomize)
	return len(d), StringIO(d)

#} END routines

#{ Stream Utilities

class DummyStream(object):
		def __init__(self):
			self.was_read = False
			self.bytes = 0
			self.closed = False
			
		def read(self, size):
			self.was_read = True
			self.bytes = size
			
		def close(self):
			self.closed = True
			
		def _assert(self):
			assert self.was_read


class DeriveTest(OStream):
	def __init__(self, sha, type, size, stream, *args, **kwargs):
		self.myarg = kwargs.pop('myarg')
		self.args = args
		
	def _assert(self):
		assert self.args
		assert self.myarg

#} END stream utilitiess

