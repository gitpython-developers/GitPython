# test_performance.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *
from time import time

class TestPerformance(TestBase):

	def _query_commit_info(self, c):
		c.author
		c.authored_date
		c.committer
		c.committed_date
		c.message
		
	def test_iteration(self):
		num_objs = 0
		num_commits = 0
		
		# find the first commit containing the given path - always do a full 
		# iteration ( restricted to the path in question ), but in fact it should 
		# return quite a lot of commits, we just take one and hence abort the operation
		
		st = time()
		for c in self.rorepo.iter_commits('0.1.6'):
			num_commits += 1
			self._query_commit_info(c)
			for obj in c.tree.traverse():
				obj.size
				num_objs += 1
			# END for each object
		# END for each commit
		elapsed_time = time() - st
		print "Traversed %i Trees and a total of %i unchached objects in %s [s] ( %f objs/s )" % (num_commits, num_objs, elapsed_time, num_objs/elapsed_time) 
		
	def test_commit_traversal(self):
		num_commits = 0
		
		st = time()
		for c in self.rorepo.commit('0.1.6').traverse(branch_first=False):
			num_commits += 1
			#if c.message == "initial project":
			#	raise "stop"
			self._query_commit_info(c)
		# END for each traversed commit
		elapsed_time = time() - st
		print "Traversed %i Commits in %s [s] ( %f objs/s )" % (num_commits, elapsed_time, num_commits/elapsed_time)
