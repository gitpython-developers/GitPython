# helper.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
from git import Repo
from unittest import TestCase

GIT_REPO = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

def fixture_path(name):
	test_dir = os.path.dirname(os.path.dirname(__file__))
	return os.path.join(test_dir, "fixtures", name)

def fixture(name):
	return open(fixture_path(name)).read()

def absolute_project_path():
	return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
	
	
class ListProcessAdapter(object):
	"""Allows to use lists as Process object as returned by SubProcess.Popen.
	Its tailored to work with the test system only"""
	
	class Stream(object):
		"""Simple stream emulater meant to work only with tests"""
		def __init__(self, data):
			self.data = data
			self.cur_iter = None
		
		def __iter__(self):
			dat = self.data
			if isinstance(dat, basestring):
				dat = dat.splitlines()
			if self.cur_iter is None:
				self.cur_iter = iter(dat)
			return self.cur_iter
			
		def read(self):
			dat = self.data
			if isinstance(dat, (tuple,list)):
				dat = "\n".join(dat)
			return dat
			
		def next(self):
			if self.cur_iter is None:
				self.cur_iter = iter(self)
			return self.cur_iter.next()
			
	# END stream 
	
	def __init__(self, input_list_or_string):
		self.stdout = self.Stream(input_list_or_string)
		self.stderr = self.Stream('')
		
	def wait(self):
		return 0
		
	poll = wait
	
	
def with_bare_rw_repo(func):
	"""
	Decorator providing a specially made read-write repository to the test case
	decorated with it. The test case requires the following signature::
		def case(self, rw_repo)
	
	The rwrepo will be a bare clone or the types rorepo. Once the method finishes, 
	it will be removed completely.
	
	Use this if you want to make purely index based adjustments, change refs, create
	heads, generally operations that do not need a working tree.
	"""
	def bare_repo_creator(self):
		rw_repo = None
		try:
			return func(self, rw_repo)
		finally:
			pass
		# END cleanup
	# END bare repo creator
	bare_repo_creator.__name__ = func.__name__
	return bare_repo_creator
	
def with_rw_repo(func, working_tree_ref='0.1.6'):
	"""
	Same as with_bare_repo, but clones the rorepo as non-bare repository, checking 
	out the working tree at the given working_tree_ref.
	
	This repository type is more costly due to the working copy checkout.
	"""
	def repo_creator(self):
		rw_repo = None
		try:
			return func(self, rw_repo)
		finally:
			pass
		# END cleanup
	# END bare repo creator
	repo_creator.__name__ = func.__name__
	return repo_creator
	
def with_rw_and_rw_remote_repo(func):
	"""
	Same as with_rw_repo, but also provides a writable remote repository from which the
	rw_repo has been forked. The remote repository was cloned as bare repository from 
	the rorepo, wheras the rw repo has a working tree and was cloned from the remote repository.
	
	The following scetch demonstrates this::
	 rorepo ---<bare clone>---> rw_remote_repo ---<clone>---> rw_repo
	
	The test case needs to support the following signature::
		def case(self, rw_repo, rw_remote_repo)
		
	This setup allows you to test push and pull scenarios and hooks nicely.
	"""
	def remote_repo_creator(self):
		rw_repo = None
		rw_remote_repo = None
		try:
			return func(self, rw_repo, rw_remote_repo)
		finally:
			pass
		# END cleanup
	# END bare repo creator
	remote_repo_creator.__name__ = func.__name__
	return remote_repo_creator
	
	
class TestBase(TestCase):
	"""
	Base Class providing default functionality to all tests such as:
	
	- Utility functions provided by the TestCase base of the unittest method such as::
		self.fail("todo")
		self.failUnlessRaises(...)
		
	- Class level repository which is considered read-only as it is shared among 
	  all test cases in your type.
	  Access it using:: 
	   self.rorepo	# 'ro' stands for read-only
	   
	  The rorepo is in fact your current project's git repo. If you refer to specific 
	  shas for your objects, be sure you choose some that are part of the immutable portion 
	  of the project history ( to assure tests don't fail for others ).
	"""
	
	@classmethod
	def setUpAll(cls):
		"""
		Dynamically add a read-only repository to our actual type. This way 
		each test type has its own repository
		"""
		cls.rorepo = Repo(GIT_REPO)
		
