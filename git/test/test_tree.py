# test_tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
from git.test.lib import TestBase
from git import (
    Tree,
    Blob
)

from io import BytesIO


class TestTree(TestBase):

    def test_serializable(self):
        # tree at the given commit contains a submodule as well
        roottree = self.rorepo.tree('6c1faef799095f3990e9970bc2cb10aa0221cf9c')
        for item in roottree.traverse(ignore_self=False):
            if item.type != Tree.type:
                continue
            # END skip non-trees
            tree = item
            # trees have no dict
            self.failUnlessRaises(AttributeError, setattr, tree, 'someattr', 1)

            orig_data = tree.data_stream.read()
            orig_cache = tree._cache

            stream = BytesIO()
            tree._serialize(stream)
            assert stream.getvalue() == orig_data

            stream.seek(0)
            testtree = Tree(self.rorepo, Tree.NULL_BIN_SHA, 0, '')
            testtree._deserialize(stream)
            assert testtree._cache == orig_cache

            # replaces cache, but we make sure of it
            del(testtree._cache)
            testtree._deserialize(stream)
        # END for each item in tree

    def test_traverse(self):
        root = self.rorepo.tree('0.1.6')
        num_recursive = 0
        all_items = list()
        for obj in root.traverse():
            if "/" in obj.path:
                num_recursive += 1

            assert isinstance(obj, (Blob, Tree))
            all_items.append(obj)
        # END for each object
        assert all_items == root.list_traverse()

        # limit recursion level to 0 - should be same as default iteration
        assert all_items
        assert 'CHANGES' in root
        assert len(list(root)) == len(list(root.traverse(depth=1)))

        # only choose trees
        trees_only = lambda i, d: i.type == "tree"
        trees = list(root.traverse(predicate=trees_only))
        assert len(trees) == len(list(i for i in root.traverse() if trees_only(i, 0)))

        # test prune
        lib_folder = lambda t, d: t.path == "lib"
        pruned_trees = list(root.traverse(predicate=trees_only, prune=lib_folder))
        assert len(pruned_trees) < len(trees)

        # trees and blobs
        assert len(set(trees) | set(root.trees)) == len(trees)
        assert len(set(b for b in root if isinstance(b, Blob)) | set(root.blobs)) == len(root.blobs)
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
            # NOTE: on py3, / doesn't work with strings anymore ...
            assert root[item.path] == item == root / item.path
        # END for each item
        assert found_slash
