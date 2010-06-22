from test.testlib import *
from git.objects.fun import (
								traverse_tree_recursive,
								traverse_trees_recursive
							)

from git.index.fun import (
							aggressive_tree_merge
							)

from git.index import IndexFile
from stat import (
					S_IFDIR, 
					S_IFREG,
					S_IFLNK
				)

class TestFun(TestBase):
	
	def _assert_index_entries(self, entries, trees):
		index = IndexFile.from_tree(self.rorepo, *trees)
		assert entries
		assert len(index.entries) == len(entries)
		for entry in entries:
			assert (entry.path, entry.stage) in index.entries
		# END assert entry matches fully
	
	def test_aggressive_tree_merge(self):
		# head tree with additions, removals and modification compared to its predecessor
		odb = self.rorepo.odb
		HC = self.rorepo.commit("6c1faef799095f3990e9970bc2cb10aa0221cf9c") 
		H = HC.tree
		B = HC.parents[0].tree
		
		# entries from single tree
		trees = [H.sha]
		self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)
		
		# from multiple trees
		trees = [B.sha, H.sha]
		self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)
		
		# three way, no conflict
		tree = self.rorepo.tree
		B = tree("35a09c0534e89b2d43ec4101a5fb54576b577905")
		H = tree("4fe5cfa0e063a8d51a1eb6f014e2aaa994e5e7d4")
		M = tree("1f2b19de3301e76ab3a6187a49c9c93ff78bafbd")
		trees = [B.sha, H.sha, M.sha]
		self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)
		
		# three-way, conflict in at least one file, both modified
		B = tree("a7a4388eeaa4b6b94192dce67257a34c4a6cbd26")
		H = tree("f9cec00938d9059882bb8eabdaf2f775943e00e5")
		M = tree("44a601a068f4f543f73fd9c49e264c931b1e1652")
		trees = [B.sha, H.sha, M.sha]
		self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)

	def make_tree(odb, entries):
		"""create a tree from the given tree entries and safe it to the database"""
		
	
	@with_rw_repo('0.1.6')
	def test_three_way_merge(self, rwrepo):
		def mkfile(name, sha, executable=0):
			return (sha, S_IFREG | 644 | executable*0111, name)
		def mkcommit(name, sha):
			return (sha, S_IFDIR | S_IFLNK, name)
		odb = rwrepo.odb
		
	
	def _assert_tree_entries(self, entries, num_trees):
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
		self._assert_tree_entries(entries, 2)
		
		oentries = traverse_trees_recursive(odb, [H.sha, B_old.sha], '')
		assert len(oentries) == len(entries)
		self._assert_tree_entries(oentries, 2)
		
		# single tree
		is_no_tree = lambda i, d: i.type != 'tree'
		entries = traverse_trees_recursive(odb, [B.sha], '')
		assert len(entries) == len(list(B.traverse(predicate=is_no_tree)))
		self._assert_tree_entries(entries, 1)
		
		# two trees
		entries = traverse_trees_recursive(odb, [B.sha, H.sha], '')
		self._assert_tree_entries(entries, 2)
		
		# tree trees
		entries = traverse_trees_recursive(odb, [B.sha, H.sha, M.sha], '')
		self._assert_tree_entries(entries, 3)
		
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
