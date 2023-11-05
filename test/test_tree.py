# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from io import BytesIO

from git.objects import Tree, Blob
from test.lib import TestBase

import os.path as osp


class TestTree(TestBase):
    def test_serializable(self):
        # Tree at the given commit contains a submodule as well.
        roottree = self.rorepo.tree("6c1faef799095f3990e9970bc2cb10aa0221cf9c")
        for item in roottree.traverse(ignore_self=False):
            if item.type != Tree.type:
                continue
            # END skip non-trees
            tree = item
            # Trees have no dict.
            self.assertRaises(AttributeError, setattr, tree, "someattr", 1)

            orig_data = tree.data_stream.read()
            orig_cache = tree._cache

            stream = BytesIO()
            tree._serialize(stream)
            assert stream.getvalue() == orig_data

            stream.seek(0)
            testtree = Tree(self.rorepo, Tree.NULL_BIN_SHA, 0, "")
            testtree._deserialize(stream)
            assert testtree._cache == orig_cache

            # Replaces cache, but we make sure of it.
            del testtree._cache
            testtree._deserialize(stream)
        # END for each item in tree

    def test_traverse(self):
        root = self.rorepo.tree("0.1.6")
        num_recursive = 0
        all_items = []
        for obj in root.traverse():
            if "/" in obj.path:
                num_recursive += 1

            assert isinstance(obj, (Blob, Tree))
            all_items.append(obj)
        # END for each object
        assert all_items == root.list_traverse()

        # Limit recursion level to 0 - should be same as default iteration.
        assert all_items
        assert "CHANGES" in root
        assert len(list(root)) == len(list(root.traverse(depth=1)))

        # Only choose trees.
        trees_only = lambda i, d: i.type == "tree"
        trees = list(root.traverse(predicate=trees_only))
        assert len(trees) == len([i for i in root.traverse() if trees_only(i, 0)])

        # Test prune.
        lib_folder = lambda t, d: t.path == "lib"
        pruned_trees = list(root.traverse(predicate=trees_only, prune=lib_folder))
        assert len(pruned_trees) < len(trees)

        # Trees and blobs.
        assert len(set(trees) | set(root.trees)) == len(trees)
        assert len({b for b in root if isinstance(b, Blob)} | set(root.blobs)) == len(root.blobs)
        subitem = trees[0][0]
        assert "/" in subitem.path
        assert subitem.name == osp.basename(subitem.path)

        # Check that at some point the traversed paths have a slash in them.
        found_slash = False
        for item in root.traverse():
            assert osp.isabs(item.abspath)
            if "/" in item.path:
                found_slash = True
            # END check for slash

            # Slashes in paths are supported as well.
            # NOTE: On Python 3, / doesn't work with strings anymore...
            assert root[item.path] == item == root / item.path
        # END for each item
        assert found_slash
