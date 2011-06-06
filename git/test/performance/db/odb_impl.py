"""Performance tests for object store"""

from time import time
import sys
import stat

from git.test.performance.lib import (
	TestBigRepoR,
	GlobalsItemDeletorMetaCls
	)

class PerfBaseDeletorMetaClass(GlobalsItemDeletorMetaCls):
	ModuleToDelete = 'TestObjDBPerformanceBase'
	

class TestObjDBPerformanceBase(TestBigRepoR):
	__metaclass__ = PerfBaseDeletorMetaClass
	
	#{ Configuration 
	RepoCls = None	# to be set by subclass
	#} END configuration
	
	def test_random_access_test(self):
		repo = self.rorepo
	
		# GET COMMITS
		st = time()
		root_commit = repo.commit(self.head_sha_2k)
		commits = list(root_commit.traverse())
		nc = len(commits)
		elapsed = time() - st
		
		print >> sys.stderr, "%s: Retrieved %i commits from ObjectStore in %g s ( %f commits / s )" % (type(repo.odb), nc, elapsed, nc / elapsed)
			
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
		
		print >> sys.stderr, "%s: Retrieved %i objects from %i commits in %g s ( %f objects / s )" % (type(repo.odb), nt, len(commits), elapsed, nt / elapsed)
		
		# GET BLOBS
		st = time()
		nb = 0
		too_many = 15000
		data_bytes = 0
		for blob_list in blobs_per_commit:
			for blob in blob_list:
				data_bytes += len(blob.data_stream.read())
			# END for each blobsha
			nb += len(blob_list)
			if nb > too_many:
				break
		# END for each bloblist
		elapsed = time() - st
		
		print >> sys.stderr, "%s: Retrieved %i blob (%i KiB) and their data in %g s ( %f blobs / s, %f KiB / s )" % (type(repo.odb), nb, data_bytes/1000, elapsed, nb / elapsed, (data_bytes / 1000) / elapsed)
		
		
