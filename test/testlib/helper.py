# helper.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os

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
