# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import os
import os.path as osp
import subprocess
from io import BytesIO
from pathlib import Path

import ddt
import pytest

from git.objects import Blob, Tree
from git.objects.fun import tree_entries_from_data, tree_to_stream
from git.objects.tree import TreeModifier
from git.repo import Repo
from git.util import cwd
from test.lib import TestBase, with_rw_directory

from .lib.helper import PathLikeMock, with_rw_repo


@ddt.ddt
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

    def test_valid_unusual_tree_names_round_trip(self):
        names = ["a b", "a\nb", "a\tb", "café", ".gitignore"]
        if os.name != "nt":
            names.extend(["a\\b", "a:b", "C:relative"])
        cache = []
        modifier = TreeModifier(cache)
        for name in names:
            modifier.add(b"a" * 20, 0o100644, name)
        modifier.set_done()
        data = BytesIO()
        tree_to_stream(cache, data.write)
        assert tree_entries_from_data(data.getvalue()) == cache

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

    @ddt.data("", ".", "..", ".git", ".GIT", "git~1", ".git. ", ".g\u200cit", "a/b", "a\0b")
    def test_tree_names_are_checked_at_construction_and_serialization(self, name):
        cache = []
        with pytest.raises(ValueError):
            TreeModifier(cache).add(b"a" * 20, 0o100644, name)
        assert not cache
        with pytest.raises(ValueError):
            tree_to_stream([(b"a" * 20, 0o100644, name)], BytesIO().write)

    @ddt.data(
        ".gitmodules",
        ".GITMODULES",
        ".gitmodules ",
        ".gi\u200ctmodules",
        "gitmod~1",
        "gitmod~2",
        "gitmod~3",
        "GITMOD~4",
        "gi7eba~1",
        "GI7EBA~9",
        "GI7EB~10",
        "GI7EB~11",
        "GI7EB~99",
        "GI7E~100",
        "GI7E~101",
        "GI7E~999",
        "GI7~1000",
        "GI7~9999",
        "GI~10000",
        "GI~99999",
        "G~100000",
        "G~999999",
        "~1000000",
        "~9999999",
        "Gi7Eb~42",
        "gi7e~120",
        "GITMOD~4 . ",
        "GI7EB~10. ",
        "GI7E~100:$DATA",
        "~1000000 . :$DATA",
    )
    def test_gitmodules_symlink_entries_are_rejected(self, name):
        """A symbolic link named like the submodule configuration would make Git read
        it from outside the repository, so such an entry is refused in both
        directions. A regular file with the same name is the normal case."""
        symlink_mode = 0o120000
        cache = []
        with pytest.raises(ValueError):
            TreeModifier(cache).add(b"a" * 20, symlink_mode, name)
        assert not cache
        with pytest.raises(ValueError):
            tree_to_stream([(b"a" * 20, symlink_mode, name)], BytesIO().write)
        raw = b"120000 " + name.encode() + b"\0" + b"a" * 20
        with pytest.raises(ValueError):
            tree_entries_from_data(raw)

        TreeModifier(cache).add(b"a" * 20, 0o100644, name)
        assert cache == [(b"a" * 20, 0o100644, name)]
        data = BytesIO()
        tree_to_stream(cache, data.write)
        assert tree_entries_from_data(data.getvalue()) == cache

    @ddt.data(
        "gitmod~0",
        "gitmod~5",
        "gitmod~10",
        "GI7EBA~",
        "GI7EBA~0",
        "GI7EBA~~1",
        "GI7EBA~X",
        "GI7EBA~10",
        "Gx7EBA~1",
        "GI7EBX~1",
        "GI7EB~1",
        "GI7EB~01",
        "GI7EB~1X",
        "GI7EB~100",
        "GI7E~10",
        "GI7E~010",
        "GI7E~1000",
        "GI7~100",
        "GI7~0100",
        "GI7~10000",
        "GI~1000",
        "GI~01000",
        "GI~100000",
        "G~10000",
        "G~010000",
        "G~1000000",
        "~100000",
        "~0100000",
        "~10000000",
        "GI7EBA~\u0661",
        "GI7EB~1\uff10",
        "GI7EB~10x",
        "GI7EB~10.x",
        " GI7EB~10",
        "GI7EB~10\n",
        "GI7EB~10\t",
        "GI7EB~10x:$DATA",
        ".gitmodules x",
        ".gitmodules .x",
        ".gitmodules,:$DATA",
    )
    def test_gitmodules_short_name_near_misses_round_trip(self, name):
        """Only exact aliases are forbidden, and only for symbolic links."""
        for mode in (0o100644, 0o120000):
            cache = []
            TreeModifier(cache).add(b"a" * 20, mode, name)
            assert cache == [(b"a" * 20, mode, name)]
            data = BytesIO()
            tree_to_stream(cache, data.write)
            raw = ("%o " % mode).encode() + name.encode() + b"\0" + b"a" * 20
            assert data.getvalue() == raw
            assert tree_entries_from_data(raw) == cache

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

        def trees_only(i, _d):
            return i.type == "tree"

        trees = list(root.traverse(predicate=trees_only))
        assert len(trees) == len([i for i in root.traverse() if trees_only(i, 0)])

        # Test prune.

        def lib_folder(t, _d):
            return t.path == "lib"

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

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_string_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        blob = repo.tree() / ".gitignore"
        assert isinstance(blob, Blob)
        assert blob.hexsha == "787b3d442a113b78e343deb585ab5531eb7187fa"

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_pathlike_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        blob = repo.tree() / PathLikeMock(".gitignore")
        assert isinstance(blob, Blob)
        assert blob.hexsha == "787b3d442a113b78e343deb585ab5531eb7187fa"

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_invalid_string_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        with pytest.raises(KeyError):
            repo.tree() / "doesnotexist"

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_invalid_pathlike_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        with pytest.raises(KeyError):
            repo.tree() / PathLikeMock("doesnotexist")

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_nested_string_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        blob = repo.tree() / "git/__init__.py"
        assert isinstance(blob, Blob)
        assert blob.hexsha == "d87dcbdbb65d2782e14eea27e7f833a209c052f3"

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_nested_pathlike_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        blob = repo.tree() / PathLikeMock("git/__init__.py")
        assert isinstance(blob, Blob)
        assert blob.hexsha == "d87dcbdbb65d2782e14eea27e7f833a209c052f3"

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_folder_string_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        tree = repo.tree() / "git"
        assert isinstance(tree, Tree)
        assert tree.hexsha == "ec8ae429156d65afde4bbb3455570193b56f0977"

    @with_rw_repo("0.3.2.1")
    def test_repo_lookup_folder_pathlike_path(self, rw_repo):
        repo = Repo(rw_repo.git_dir)
        tree = repo.tree() / PathLikeMock("git")
        assert isinstance(tree, Tree)
        assert tree.hexsha == "ec8ae429156d65afde4bbb3455570193b56f0977"
