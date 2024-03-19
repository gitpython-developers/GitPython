# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from io import BytesIO
import os.path as osp
from pathlib import Path
import subprocess

from git.objects import Blob, Tree
from git.util import cwd

from test.lib import TestBase, with_rw_directory


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

    @with_rw_directory
    def _get_git_ordered_files(self, rw_dir):
        """Get files as git orders them, to compare in test_tree_modifier_ordering."""
        # Create directory contents.
        Path(rw_dir, "file").mkdir()
        for filename in (
            "bin",
            "bin.d",
            "file.to",
            "file.toml",
            "file.toml.bin",
            "file0",
        ):
            Path(rw_dir, filename).touch()
        Path(rw_dir, "file", "a").touch()

        with cwd(rw_dir):
            # Prepare the repository.
            subprocess.run(["git", "init", "-q"], check=True)
            subprocess.run(["git", "add", "."], check=True)
            subprocess.run(["git", "commit", "-m", "c1"], check=True)

            # Get git output from which an ordered file list can be parsed.
            rev_parse_command = ["git", "rev-parse", "HEAD^{tree}"]
            tree_hash = subprocess.check_output(rev_parse_command).decode().strip()
            cat_file_command = ["git", "cat-file", "-p", tree_hash]
            cat_file_output = subprocess.check_output(cat_file_command).decode()

        return [line.split()[-1] for line in cat_file_output.split("\n") if line]

    def test_tree_modifier_ordering(self):
        """TreeModifier.set_done() sorts files in the same order git does."""
        git_file_names_in_order = self._get_git_ordered_files()

        hexsha = "6c1faef799095f3990e9970bc2cb10aa0221cf9c"
        roottree = self.rorepo.tree(hexsha)
        blob_mode = Tree.blob_id << 12
        tree_mode = Tree.tree_id << 12

        files_in_desired_order = [
            (blob_mode, "bin"),
            (blob_mode, "bin.d"),
            (blob_mode, "file.to"),
            (blob_mode, "file.toml"),
            (blob_mode, "file.toml.bin"),
            (blob_mode, "file0"),
            (tree_mode, "file"),
        ]
        mod = roottree.cache
        for file_mode, file_name in files_in_desired_order:
            mod.add(hexsha, file_mode, file_name)
        # end for each file

        def file_names_in_order():
            return [t[1] for t in files_in_desired_order]

        def names_in_mod_cache():
            a = [t[2] for t in mod._cache]
            here = file_names_in_order()
            return [e for e in a if e in here]

        mod.set_done()
        assert names_in_mod_cache() == git_file_names_in_order, "set_done() performs git-sorting"

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
