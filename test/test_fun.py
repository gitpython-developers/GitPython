# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from io import BytesIO
from os import stat
from stat import S_IFDIR, S_IFLNK, S_IFREG, S_IXUSR
from pathlib import Path

import ddt
from gitdb.base import IStream

from git.index import IndexFile
from git.index.fun import stat_mode_to_index_mode
from git.objects import Tree
from git.repo.fun import find_worktree_git_dir
from git.util import bin_to_hex
from test.lib import TestBase, with_rw_repo
from test.lib.fixtures import fixture_repo, read_only_fixture


@ddt.ddt
class TestFun(TestBase):
    @staticmethod
    def merge_trees(repo, trees):
        return list(IndexFile.new(repo, *(tree.hex() for tree in trees)).iter_entries())

    def _assert_index_entries(self, entries, trees):
        index = IndexFile.from_tree(self.rorepo, *[self.rorepo.tree(bin_to_hex(t).decode("ascii")) for t in trees])
        assert entries
        assert len([(e.path, e.stage) for e in index.iter_entries()]) == len(entries)
        for entry in entries:
            assert (entry.path, entry.stage) in [(e.path, e.stage) for e in index.iter_entries()]
        # END assert entry matches fully

    def test_aggressive_tree_merge(self):
        # Head tree with additions, removals and modification compared to its
        # predecessor.
        repo = self.rorepo
        HC = self.rorepo.commit("6c1faef799095f3990e9970bc2cb10aa0221cf9c")
        H = HC.tree
        B = HC.parents[0].tree

        # Entries from single tree.
        trees = [H.binsha]
        self._assert_index_entries(self.merge_trees(repo, trees), trees)

        # From multiple trees.
        trees = [B.binsha, H.binsha]
        self._assert_index_entries(self.merge_trees(repo, trees), trees)

        # Three way, no conflict.
        tree = self.rorepo.tree
        B = tree("35a09c0534e89b2d43ec4101a5fb54576b577905")
        H = tree("4fe5cfa0e063a8d51a1eb6f014e2aaa994e5e7d4")
        M = tree("1f2b19de3301e76ab3a6187a49c9c93ff78bafbd")
        trees = [B.binsha, H.binsha, M.binsha]
        self._assert_index_entries(self.merge_trees(repo, trees), trees)

        # Three-way, conflict in at least one file, both modified.
        B = tree("a7a4388eeaa4b6b94192dce67257a34c4a6cbd26")
        H = tree("f9cec00938d9059882bb8eabdaf2f775943e00e5")
        M = tree("44a601a068f4f543f73fd9c49e264c931b1e1652")
        trees = [B.binsha, H.binsha, M.binsha]
        self._assert_index_entries(self.merge_trees(repo, trees), trees)

        # Too many trees.
        self.assertRaises(ValueError, self.merge_trees, repo, trees * 2)

    def test_three_way_merge(self):
        def assert_entries(entries, num_entries, has_conflict=False):
            assert len(entries) == num_entries
            assert has_conflict == any(e.stage != 0 for e in entries)

        with fixture_repo("fun.sh", "merge-trees", write=True) as repo:
            root = Path(repo.working_tree_dir).parent
            trees = {path.name: bytes.fromhex(path.read_text().strip()) for path in root.iterdir() if path.is_file()}
            base = trees["base"]
            for ours, theirs, count, conflict in (
                ("add-ours", "add-theirs", 3, False),
                ("only-ours", "only-theirs", 2, False),
                ("only-ours", "same-name-theirs", 2, True),
                ("only-ours", "gitlink-one", 2, True),
                ("only-ours", "only-ours", 1, False),
                ("modify-ours", "modify-theirs", 3, True),
                ("gitlink-base", "executable-base", 3, True),
            ):
                assert_entries(self.merge_trees(repo, [base, trees[ours], trees[theirs]]), count, conflict)

            for is_them in range(2):
                for changed, oid, mode in (
                    ("modify-ours", b"\2" * 20, S_IFREG | 0o644),
                    ("gitlink-base", b"\1" * 20, S_IFDIR | S_IFLNK),
                ):
                    sides = [trees[changed], base]
                    if is_them:
                        sides.reverse()
                    entries = self.merge_trees(repo, [base, *sides])
                    assert len(entries) == 1 and entries[0].binsha == oid and entries[0].mode == mode

                sides = [trees["modify-ours"], trees["empty"]]
                if is_them:
                    sides.reverse()
                assert_entries(self.merge_trees(repo, [base, *sides]), 2, True)
        # END handle ours, theirs

    def test_stat_mode_to_index_mode(self):
        modes = (
            0o600,
            0o611,
            0o640,
            0o641,
            0o644,
            0o650,
            0o651,
            0o700,
            0o711,
            0o740,
            0o744,
            0o750,
            0o751,
            0o755,
        )
        for mode in modes:
            expected_mode = S_IFREG | (mode & S_IXUSR and 0o755 or 0o644)
            assert stat_mode_to_index_mode(mode) == expected_mode
        # END for each mode

    def test_linked_worktree_traversal(self):
        """Identify a linked worktree from an immutable scripted .git file."""
        root = read_only_fixture("fun.sh", "worktree", self.rorepo.working_dir, self.rorepo.head.commit.hexsha)
        dotgit = root / "worktree_repo/.git"
        self.assertTrue(stat(dotgit).st_mode & S_IFREG)
        gitdir = find_worktree_git_dir(dotgit)
        self.assertIsNotNone(gitdir)
        self.assertTrue(stat(gitdir).st_mode & S_IFDIR)

    @with_rw_repo("0.1.6")
    def test_tree_names_from_git_preserve_undecodable_bytes(self, repo):
        tree = Tree(repo, repo._null_binsha, path="")
        tree._cache = [(b"a" * repo._oid_size, 0o100644, "\udc9f")]
        data = BytesIO()
        tree._serialize(data)
        data.seek(0)
        stored = repo.odb.store(IStream("tree", len(data.getvalue()), data))
        assert Tree(repo, stored.binsha, path="")._cache == tree._cache
