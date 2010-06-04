"""Performance tests for object store"""

from time import time
import sys
import stat

from lib import (
	TestBigRepoR
	)


class TestObjDBPerformance(TestBigRepoR):
	
	def test_random_access(self):
		
		# GET COMMITS
		# TODO: use the actual db for this
		st = time()
		root_commit = self.gitrorepo.commit(self.head_sha_2k)
		commits = list(root_commit.traverse())
		nc = len(commits)
		elapsed = time() - st
		
		print >> sys.stderr, "Retrieved %i commits from ObjectStore in %g s ( %f commits / s )" % (nc, elapsed, nc / elapsed)
			
			
		# GET TREES
		# walk all trees of all commits
		st = time()
		blobs_per_commit = list()
		nt = 0
		for commit in commits:
			tree = commit.tree
			blobs = list()
			for item in tree.traverse():
				nt += 1
				if item.type == 'blob':
					blobs.append(item)
				# direct access for speed
			# END while trees are there for walking
			blobs_per_commit.append(blobs)
		# END for each commit
		elapsed = time() - st
		
		print >> sys.stderr, "Retrieved %i objects from %i commits in %g s ( %f objects / s )" % (nt, len(commits), elapsed, nt / elapsed)
		
		# GET BLOBS
		st = time()
		nb = 0
		too_many = 15000
		for blob_list in blobs_per_commit:
			for blob in blob_list:
				blob.data
			# END for each blobsha
			nb += len(blob_list)
			if nb > too_many:
				break
		# END for each bloblist
		elapsed = time() - st
		
		print >> sys.stderr, "Retrieved %i blob and their data in %g s ( %f blobs / s )" % (nb, elapsed, nb / elapsed)
