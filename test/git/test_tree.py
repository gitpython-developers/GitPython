# test_tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
from test.testlib import *
from git import *

class TestTree(TestCase):
    
    def setUp(self):
        self.repo = Repo(GIT_REPO)

    
        
    def test_traverse(self):
        root = self.repo.tree('0.1.6')
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
        assert len(list(root)) == len(list(root.traverse(depth=1)))
        
        # only choose trees
        trees_only = lambda i,d: i.type == "tree"
        trees = list(root.traverse(predicate = trees_only))
        assert len(trees) == len(list( i for i in root.traverse() if trees_only(i,0) ))
        
        # test prune
        lib_folder = lambda t,d: t.path == "lib"
        pruned_trees = list(root.traverse(predicate = trees_only,prune = lib_folder))
        assert len(pruned_trees) < len(trees)
        
        # trees and blobs
        assert len(set(trees)|set(root.trees)) == len(trees)
        assert len(set(b for b in root if isinstance(b, Blob)) | set(root.blobs)) == len( root.blobs )
        subitem = trees[0][0]
        assert "/" in subitem.path
        assert subitem.name == os.path.basename(subitem.path)
        
        # assure that at some point the traversed paths have a slash in them
        found_slash = False
        for item in root.traverse():
            assert os.path.isabs(item.abspath)
            if '/' in item.path:
                found_slash = True
            # END check for slash
            
            # slashes in paths are supported as well 
            assert root[item.path] == item == root/item.path
        # END for each item
        assert found_slash
  
    def test_repr(self):
        tree = Tree(self.repo, 'abc')
        assert_equal('<git.Tree "abc">', repr(tree))
