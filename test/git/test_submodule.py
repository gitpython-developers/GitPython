# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestSubmodule(TestBase):

	kCOTag = '0.1.6'

	def _do_base_tests(self, rwrepo):
		"""Perform all tests in the given repository, it may be bare or nonbare"""
		
		# uncached path/url - retrieves information from .gitmodules file
		
		# changing the root_tree yields new values when querying them (i.e. cache is cleared)
		
		
		# size is invalid
		self.failUnlessRaises(ValueError, getattr, sm, 'size')
		
		# fails if tree has no gitmodule file
		
		if rwrepo.bare:
			# module fails
			pass
		else:
			# get the module repository
			pass
		# END bare handling
	
	@with_rw_repo(kCOTag)
	def test_base_rw(self, rwrepo):
		self._do_base_tests(rwrepo)
		
	@with_bare_rw_repo
	def test_base_bare(self, rwrepo):
		self._do_base_tests(rwrepo)
		

