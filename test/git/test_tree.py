# test_tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestTree(TestCase):
	
	def setUp(self):
		self.repo = Repo(GIT_REPO)

	
		
	def test_traverse(self):
		root = self.repo.tree()
		num_recursive = 0
		all_items = list()
		for obj in root.traverse():
			if "/" in obj.path:
				num_recursive += 1
				
			assert isinstance(obj, (Blob, Tree))
			all_items.append(obj)
		# END for each object
		# limit recursion level to 0 - should be same as default iteration
		assert all_items
		assert 'CHANGES' in root
		assert len(list(root)) == len(list(root.traverse(max_depth=0)))
		
		# only choose trees
		trees_only = lambda i: i.type == "tree"
		trees = list(root.traverse(predicate = trees_only))
		assert len(trees) == len(list( i for i in root.traverse() if trees_only(i) ))
		
		# test prune
		lib_folder = lambda t: t.path == "lib"
		pruned_trees = list(root.traverse(predicate = trees_only,prune = lib_folder))
		assert len(pruned_trees) < len(trees)
		
		# trees and blobs
		assert len(set(trees)|set(root.trees)) == len(trees)
		assert len(set(b for b in root if isinstance(b, Blob)) | set(root.blobs)) == len( root.blobs )
  
	def test_repr(self):
		tree = Tree(self.repo, id='abc')
		assert_equal('<git.Tree "abc">', repr(tree))
