from test.testlib import *
from git.objects.fun import (
								traverse_tree_recursive,
								traverse_trees_recursive
							)

from git.index.fun import (
							aggressive_tree_merge
							)

class TestFun(TestBase):
	
	def test_aggressive_tree_merge(self):
		# head tree with additions, removals and modification compared to its predecessor
		HC = self.rorepo.commit("6c1faef799095f3990e9970bc2cb10aa0221cf9c") 
		H = HC.tree
		B = HC.parents[0].tree
		
		# test new index from single tree
	
	def _assert_entries(self, entries, num_trees):
		assert len(entries[0]) == num_trees
		for entry in entries:
			paths = set(e[2] for e in entry if e)
			
			# only one path per set of entries
			assert len(paths) == 1
		# END verify entry
		
	def test_tree_traversal(self):
		# low level tree tarversal
		odb = self.rorepo.odb
		H = self.rorepo.tree('29eb123beb1c55e5db4aa652d843adccbd09ae18')	# head tree
		M = self.rorepo.tree('e14e3f143e7260de9581aee27e5a9b2645db72de')	# merge tree
		B = self.rorepo.tree('f606937a7a21237c866efafcad33675e6539c103')	# base tree
		B_old = self.rorepo.tree('1f66cfbbce58b4b552b041707a12d437cc5f400a')	# old base tree
		
		# two very different trees
		entries = traverse_trees_recursive(odb, [B_old.sha, H.sha], '')
		self._assert_entries(entries, 2)
		
		oentries = traverse_trees_recursive(odb, [H.sha, B_old.sha], '')
		assert len(oentries) == len(entries)
		self._assert_entries(oentries, 2)
		
		# single tree
		is_no_tree = lambda i, d: i.type != 'tree'
		entries = traverse_trees_recursive(odb, [B.sha], '')
		assert len(entries) == len(list(B.traverse(predicate=is_no_tree)))
		self._assert_entries(entries, 1)
		
		# two trees
		entries = traverse_trees_recursive(odb, [B.sha, H.sha], '')
		self._assert_entries(entries, 2)
		
		# tree trees
		entries = traverse_trees_recursive(odb, [B.sha, H.sha, M.sha], '')
		self._assert_entries(entries, 3)
		
	def test_tree_traversal_single(self):
		max_count = 50
		count = 0
		odb = self.rorepo.odb
		for commit in self.rorepo.commit("29eb123beb1c55e5db4aa652d843adccbd09ae18").traverse():
			if count >= max_count:
				break
			count += 1
			entries = traverse_tree_recursive(odb, commit.tree.sha, '')
			assert entries
		# END for each commit
