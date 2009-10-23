# test_index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *
import inspect
import os
import tempfile

class TestTree(TestBase):
	
	def test_index_file_base(self):
		# read from file
		index = IndexFile(self.rorepo, fixture_path("index"))
		assert index.entries
		assert index.version > 0
		
		# test entry
		last_val = None
		entry = index.entries.itervalues().next()
		for attr in ("path","ctime","mtime","dev","inode","mode","uid",
								"gid","size","sha","stage"):
			val = getattr(entry, attr)
		# END for each method
		
		# test stage
		index_merge = IndexFile(self.rorepo, fixture_path("index_merge"))
		assert len(index_merge.entries) == 106
		assert len(list(e for e in index_merge.entries.itervalues() if e.stage != 0 ))
		
		# write the data - it must match the original
		tmpfile = tempfile.mktemp()
		index_merge.write(tmpfile)
		fp = open(tmpfile, 'r')
		assert fp.read() == fixture("index_merge")
		fp.close()
		os.remove(tmpfile)
	
	def _cmp_tree_index(self, tree, index):
		# fail unless both objects contain the same paths and blobs
		if isinstance(tree, str):
			tree = self.rorepo.commit(tree).tree
		
		num_blobs = 0
		for blob in tree.traverse(predicate = lambda e: e.type == "blob"):
			assert (blob.path,0) in index.entries
			num_blobs += 1
		# END for each blob in tree
		assert num_blobs == len(index.entries)
	
	def test_index_file_from_tree(self):
		common_ancestor_sha = "5117c9c8a4d3af19a9958677e45cda9269de1541"
		cur_sha = "4b43ca7ff72d5f535134241e7c797ddc9c7a3573"
		other_sha = "39f85c4358b7346fee22169da9cad93901ea9eb9"
		
		# simple index from tree 
		base_index = IndexFile.from_tree(self.rorepo, common_ancestor_sha)
		assert base_index.entries
		self._cmp_tree_index(common_ancestor_sha, base_index)
		
		# merge two trees - its like a fast-forward
		two_way_index = IndexFile.from_tree(self.rorepo, common_ancestor_sha, cur_sha)
		assert two_way_index.entries
		self._cmp_tree_index(cur_sha, two_way_index)
		
		# merge three trees - here we have a merge conflict
		three_way_index = IndexFile.from_tree(self.rorepo, common_ancestor_sha, cur_sha, other_sha)
		assert len(list(e for e in three_way_index.entries.values() if e.stage != 0))
		
		
		# ITERATE BLOBS
		merge_required = lambda t: t[0] != 0
		merge_blobs = list(three_way_index.iter_blobs(merge_required))
		assert merge_blobs
		assert merge_blobs[0][0] in (1,2,3)
		assert isinstance(merge_blobs[0][1], Blob)
		
		
		# writing a tree should fail with an unmerged index
		self.failUnlessRaises(GitCommandError, three_way_index.write_tree)
		
		# removed unmerged entries
		unmerged_blob_map = three_way_index.unmerged_blobs()
		assert unmerged_blob_map
		
		# pick the first blob at the first stage we find and use it as resolved version
		three_way_index.resolve_blobs( l[0][1] for l in unmerged_blob_map.itervalues() )
		tree = three_way_index.write_tree()
		assert isinstance(tree, Tree)
		num_blobs = 0
		for blob in tree.traverse(predicate=lambda item: item.type == "blob"):
			assert (blob.path,0) in three_way_index.entries
			num_blobs += 1
		# END for each blob
		assert num_blobs == len(three_way_index.entries)
	
	@with_rw_repo('0.1.6')
	def test_index_file_diffing(self, rw_repo):
		# default Index instance points to our index
		index = IndexFile(rw_repo)
		assert index.path is not None
		assert len(index.entries)
		
		# write the file back
		index.write()
		
		# could sha it, or check stats
		
		# test diff
		# resetting the head will leave the index in a different state, and the 
		# diff will yield a few changes
		cur_head_commit = rw_repo.head.reference.commit
		ref = rw_repo.head.reset('HEAD~6', index=True, working_tree=False)
		
		# diff against same index is 0
		diff = index.diff()
		assert len(diff) == 0
		
		# against HEAD as string, must be the same as it matches index
		diff = index.diff('HEAD')
		assert len(diff) == 0
		
		# against previous head, there must be a difference
		diff = index.diff(cur_head_commit)
		assert len(diff)
		
		# we reverse the result
		adiff = index.diff(str(cur_head_commit), R=True)
		odiff = index.diff(cur_head_commit, R=False)	# now its not reversed anymore
		assert adiff != odiff
		assert odiff == diff					# both unreversed diffs against HEAD
		
		# against working copy - its still at cur_commit
		wdiff = index.diff(None)
		assert wdiff != adiff
		assert wdiff != odiff
		
		# against something unusual
		self.failUnlessRaises(ValueError, index.diff, int)
