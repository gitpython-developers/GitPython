# test_performance.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from lib import *
from git import *
from time import time
import sys

class TestPerformance(TestBigRepoReadOnly):

	# ref with about 100 commits in its history
	ref_100 = '0.1.6'

	def _query_commit_info(self, c):
		c.author
		c.authored_date
		c.author_tz_offset
		c.committer
		c.committed_date
		c.committer_tz_offset
		c.message
		c.parents
		
	def test_iteration(self):
		no = 0
		nc = 0
		
		# find the first commit containing the given path - always do a full 
		# iteration ( restricted to the path in question ), but in fact it should 
		# return quite a lot of commits, we just take one and hence abort the operation
		
		st = time()
		for c in self.rorepo.iter_commits(self.ref_100):
			nc += 1
			self._query_commit_info(c)
			for obj in c.tree.traverse():
				obj.size
				no += 1
			# END for each object
		# END for each commit
		elapsed_time = time() - st
		print >> sys.stderr, "Traversed %i Trees and a total of %i unchached objects in %s [s] ( %f objs/s )" % (nc, no, elapsed_time, no/elapsed_time) 
		
	def test_commit_traversal(self):
		# bound to cat-file parsing performance
		nc = 0
		st = time()
		for c in self.gitrepo.commit(self.head_sha_2k).traverse(branch_first=False):
			nc += 1
			self._query_commit_info(c)
		# END for each traversed commit
		elapsed_time = time() - st
		print >> sys.stderr, "Traversed %i Commits in %s [s] ( %f commits/s )" % (nc, elapsed_time, nc/elapsed_time)
		
	def test_commit_iteration(self):
		# bound to stream parsing performance
		nc = 0
		st = time()
		for c in Commit.iter_items(self.gitrepo, self.head_sha_2k):
			nc += 1
			self._query_commit_info(c)
		# END for each traversed commit
		elapsed_time = time() - st
		print >> sys.stderr, "Iterated %i Commits in %s [s] ( %f commits/s )" % (nc, elapsed_time, nc/elapsed_time)
		
