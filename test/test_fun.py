# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import os.path as osp
from io import BytesIO
from os import stat
from stat import S_IFDIR, S_IFLNK, S_IFREG, S_IXUSR

import ddt
from gitdb.base import IStream
from gitdb.typ import str_tree_type

from git import Git
from git.index import IndexFile
from git.index.fun import stat_mode_to_index_mode
from git.objects import Tree
from git.repo.fun import find_worktree_git_dir
from git.util import bin_to_hex, cygpath, join_path_native
from test.lib import TestBase, with_rw_directory, with_rw_repo


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

    def mktree(self, repo, entries):
        """Create a tree from the given tree entries and safe it to the database."""
        sio = BytesIO()
        tree = Tree(repo, repo._null_binsha, path="")
        tree._cache = entries
        tree._serialize(sio)
        sio.seek(0)
        istream = repo.odb.store(IStream(str_tree_type, len(sio.getvalue()), sio))
        return istream.binsha

    @with_rw_repo("0.1.6")
    def test_three_way_merge(self, rwrepo):
        def mkfile(name, sha, executable=0):
            return (sha, S_IFREG | 0o644 | executable * 0o111, name)

        def mkcommit(name, sha):
            return (sha, S_IFDIR | S_IFLNK, name)

        def assert_entries(entries, num_entries, has_conflict=False):
            assert len(entries) == num_entries
            assert has_conflict == (len([e for e in entries if e.stage != 0]) > 0)

        mktree = self.mktree

        shaa = b"\1" * 20
        shab = b"\2" * 20
        shac = b"\3" * 20

        repo = rwrepo

        # Base tree.
        bfn = "basefile"
        fbase = mkfile(bfn, shaa)
        tb = mktree(repo, [fbase])

        # Non-conflicting new files, same data.
        fa = mkfile("1", shab)
        th = mktree(repo, [fbase, fa])
        fb = mkfile("2", shac)
        tm = mktree(repo, [fbase, fb])

        # Two new files, same base file.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 3)

        # Both delete same file, add own one.
        fa = mkfile("1", shab)
        th = mktree(repo, [fa])
        fb = mkfile("2", shac)
        tm = mktree(repo, [fb])

        # Two new files.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 2)

        # Same file added in both, differently.
        fa = mkfile("1", shab)
        th = mktree(repo, [fa])
        fb = mkfile("1", shac)
        tm = mktree(repo, [fb])

        # Expect conflict.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 2, True)

        # Same file added, different mode.
        fa = mkfile("1", shab)
        th = mktree(repo, [fa])
        fb = mkcommit("1", shab)
        tm = mktree(repo, [fb])

        # Expect conflict.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 2, True)

        # Same file added in both.
        fa = mkfile("1", shab)
        th = mktree(repo, [fa])
        fb = mkfile("1", shab)
        tm = mktree(repo, [fb])

        # Expect conflict.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 1)

        # Modify same base file, differently.
        fa = mkfile(bfn, shab)
        th = mktree(repo, [fa])
        fb = mkfile(bfn, shac)
        tm = mktree(repo, [fb])

        # Conflict, 3 versions on 3 stages.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 3, True)

        # Change mode on same base file, by making one a commit, the other executable,
        # no content change (this is totally unlikely to happen in the real world).
        fa = mkcommit(bfn, shaa)
        th = mktree(repo, [fa])
        fb = mkfile(bfn, shaa, executable=1)
        tm = mktree(repo, [fb])

        # Conflict, 3 versions on 3 stages, because of different mode.
        trees = [tb, th, tm]
        assert_entries(self.merge_trees(repo, trees), 3, True)

        for is_them in range(2):
            # Only we/they change contents.
            fa = mkfile(bfn, shab)
            th = mktree(repo, [fa])

            trees = [tb, th, tb]
            if is_them:
                trees = [tb, tb, th]
            entries = self.merge_trees(repo, trees)
            assert len(entries) == 1 and entries[0].binsha == shab

            # Only we/they change the mode.
            fa = mkcommit(bfn, shaa)
            th = mktree(repo, [fa])

            trees = [tb, th, tb]
            if is_them:
                trees = [tb, tb, th]
            entries = self.merge_trees(repo, trees)
            assert len(entries) == 1 and entries[0].binsha == shaa and entries[0].mode == fa[1]

            # One side deletes, the other changes = conflict.
            fa = mkfile(bfn, shab)
            th = mktree(repo, [fa])
            tm = mktree(repo, [])
            trees = [tb, th, tm]
            if is_them:
                trees = [tb, tm, th]
            # As one is deleted, there are only 2 entries.
            assert_entries(self.merge_trees(repo, trees), 2, True)
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

    @with_rw_directory
    def test_linked_worktree_traversal(self, rw_dir):
        """Check that we can identify a linked worktree based on a .git file."""
        git = Git(rw_dir)
        if git.version_info[:3] < (2, 5, 1):
            raise RuntimeError("worktree feature unsupported (test needs git 2.5.1 or later)")

        rw_master = self.rorepo.clone(join_path_native(rw_dir, "master_repo"))
        branch = rw_master.create_head("aaaaaaaa")
        worktree_path = join_path_native(rw_dir, "worktree_repo")
        if Git.is_cygwin():
            worktree_path = cygpath(worktree_path)
        rw_master.git.worktree("add", worktree_path, branch.name)

        dotgit = osp.join(worktree_path, ".git")
        statbuf = stat(dotgit)
        self.assertTrue(statbuf.st_mode & S_IFREG)

        gitdir = find_worktree_git_dir(dotgit)
        self.assertIsNotNone(gitdir)
        statbuf = stat(gitdir)
        self.assertTrue(statbuf.st_mode & S_IFDIR)

    @with_rw_repo("0.1.6")
    def test_tree_names_from_git_preserve_undecodable_bytes(self, repo):
        tree = Tree(repo, repo._null_binsha, path="")
        tree._cache = [(b"a" * repo._oid_size, 0o100644, "\udc9f")]
        data = BytesIO()
        tree._serialize(data)
        data.seek(0)
        stored = repo.odb.store(IStream("tree", len(data.getvalue()), data))
        assert Tree(repo, stored.binsha, path="")._cache == tree._cache
