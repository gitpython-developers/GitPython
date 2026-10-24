# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import gc
import glob
import io
import itertools
import os
import os.path as osp
import pathlib
import pickle
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from unittest import mock

import pytest

from git import (
    BadName,
    Commit,
    Git,
    GitCmdObjectDB,
    GitCommandError,
    Head,
    IndexFile,
    InvalidGitRepositoryError,
    NoSuchPathError,
    Object,
    Reference,
    Remote,
    Repo,
    Submodule,
    Tree,
)
from git.exc import BadObject, UnsafeOptionError, UnsafeProtocolError
from git.repo.fun import find_worktree_git_dir
from git.util import bin_to_hex, cwd, rmfile, rmtree
from test.lib import PathLikeMock, TestBase, fixture, with_rw_directory, with_rw_repo
from test.lib.fixtures import fixture_repo, read_only_fixture, writable_fixture


def iter_flatten(lol):
    for items in lol:
        yield from items


def flatten(lol):
    return list(iter_flatten(lol))


_tc_lock_fpaths = osp.join(osp.dirname(__file__), "../../.git/*.lock")


def _rm_lock_files():
    for lfp in glob.glob(_tc_lock_fpaths):
        rmfile(lfp)


class TestRepo(TestBase):
    def setUp(self):
        _rm_lock_files()

    def tearDown(self):
        for lfp in glob.glob(_tc_lock_fpaths):
            if osp.isfile(lfp):
                raise AssertionError("Previous TC left hanging git-lock file: {}".format(lfp))

        gc.collect()

    def test_new_should_raise_on_invalid_repo_location(self):
        path = read_only_fixture("repo.sh", "empty")
        self.assertRaises(InvalidGitRepositoryError, Repo, path)

    @with_rw_directory(script="repo.sh", args=("template",))
    def test_init_rejects_unsafe_options(self, tdir):
        template_dir = osp.join(tdir, "template")
        unsafe_options = [
            {"template": template_dir},
            {"templa": template_dir},
            {"separate_git_dir": osp.join(tdir, "git-dir")},
            {"separate_git_di": osp.join(tdir, "git-dir")},
        ]
        for index, kwargs in enumerate(unsafe_options):
            repo_dir = osp.join(tdir, f"repo-{index}")
            with self.assertRaises(UnsafeOptionError):
                Repo.init(repo_dir, **kwargs)
            assert not osp.exists(repo_dir)

    @with_rw_directory(script="repo.sh", args=("template",))
    def test_init_allows_explicitly_unsafe_options(self, tdir):
        with Repo.init(osp.join(tdir, "repo"), template=osp.join(tdir, "template"), allow_unsafe_options=True) as repo:
            assert repo.git_dir

    def test_new_should_raise_on_invalid_repo_location_within_repo(self):
        path = read_only_fixture("repo.sh", "nested") / "repo" / "subdir"
        self.assertRaises(InvalidGitRepositoryError, Repo, path)

    def test_new_should_raise_on_non_existent_path(self):
        path = read_only_fixture("repo.sh", "empty") / "foobar"
        self.assertRaises(NoSuchPathError, Repo, path)

    def test_repo_discovery_prefers_dotgit(self):
        root = read_only_fixture("repo.sh", "prefers-dotgit")
        for name in ("linked-worktree", "bare"):
            path = root / name
            with self.subTest(layout=name), Repo(path) as repo:
                expected = Git(path).rev_parse("--absolute-git-dir")
                assert osp.samefile(repo.git_dir, expected)

    def test_repo_discovery_honors_explicit_git_dir(self):
        root = read_only_fixture("repo.sh", "explicit-git-dir")
        git_dir = root / "repo.git"
        with mock.patch.dict(os.environ, {"GIT_DIR": os.fspath(git_dir)}):
            for path in (None, ""):
                with Repo(path) as repo, self.subTest(path=path):
                    assert osp.samefile(repo.git_dir, git_dir)
        worktree = root / "worktree"
        with cwd(worktree), mock.patch.dict(os.environ, {"GIT_DIR": ""}):
            with Repo() as repo:
                assert osp.samefile(repo.git_dir, worktree / ".git")

    def test_repo_discovery_uses_native_worktree_configuration(self):
        root = read_only_fixture("repo.sh", "worktree-config")
        git_dir = root / "main" / ".git"
        configured, overridden = root / "configured", root / "overridden"
        with Repo(git_dir) as reopened:
            assert osp.samefile(reopened.working_tree_dir, configured)
            assert osp.samefile(reopened.git.rev_parse("--show-toplevel"), configured)
        with mock.patch.dict(os.environ, {"GIT_WORK_TREE": str(overridden)}):
            with Repo(git_dir) as reopened:
                assert osp.samefile(reopened.working_tree_dir, overridden)
        with mock.patch.dict(os.environ, {"GIT_COMMON_DIR": str(git_dir)}):
            with Repo(git_dir) as reopened:
                assert osp.samefile(reopened.working_tree_dir, root / "main")

    def test_repo_discovery_rejects_invalid_metadata(self):
        root = read_only_fixture("repo.sh", "invalid-metadata")
        for name in (
            "HEAD",
            "commondir-empty",
            "commondir-invalid",
            "linked-worktree",
            "gitfile-text",
            "gitfile-empty",
            "gitfile-loop",
            "gitfile-invalid",
        ):
            path = root / name
            with cwd(path), self.subTest(metadata=name):
                self.assertRaises(InvalidGitRepositoryError, Repo, path)
        path = root / "empty-environment"
        for variable in ("GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"):
            with mock.patch.dict(os.environ, {variable: ""}), self.subTest(metadata=variable):
                self.assertRaises(InvalidGitRepositoryError, Repo, path)

    def test_repo_discovery_rejects_dangling_commondir(self):
        from gix import testtools

        root = read_only_fixture("repo.sh", "dangling-commondir")
        if not testtools.fixture_has_symlinks(root):
            pytest.skip("fixture filesystem cannot create symlinks")
        self.assertRaises(InvalidGitRepositoryError, Repo, root / "repo")

    def test_repo_discovery_rejects_dotgit_stat_errors(self):
        from gix import testtools

        root = read_only_fixture("repo.sh", "dotgit-loop")
        if not testtools.fixture_has_symlinks(root):
            pytest.skip("fixture filesystem cannot create symlinks")
        self.assertRaises(InvalidGitRepositoryError, Repo, root / "repo" / "child", search_parent_directories=True)

    def test_gitfile_resolution_does_not_read_storage_in_python(self):
        dotgit = read_only_fixture("repo.sh", "missing-gitfile-target") / ".git"
        reader = mock.mock_open(read_data=b"")
        with mock.patch("builtins.open", reader):
            assert find_worktree_git_dir(dotgit) is None
        reader.assert_not_called()

    def test_relative_gitfile_resolution_uses_gitfile_directory(self):
        root = read_only_fixture("repo.sh", "relative-gitfile")
        with Repo(root / "source") as source, Repo(root / "unrelated") as unrelated:
            checkout = root / "checkout"
            dotgit = checkout / ".git"
            with cwd(unrelated.working_tree_dir), Repo(checkout) as reopened:
                assert osp.samefile(reopened.git_dir, source.git_dir)
                assert osp.samefile(find_worktree_git_dir(dotgit), source.git_dir)

    def test_repo_discovery_uses_storage_environment(self):
        root = read_only_fixture("repo.sh", "storage-environment")
        git_dir, common_dir = root / "git", root / "common"
        with cwd(root), mock.patch.dict(os.environ, {"GIT_DIR": "git", "GIT_COMMON_DIR": "common"}):
            repo = Repo()
        with repo:
            assert osp.samefile(repo.common_dir, common_dir)
            assert osp.samefile(repo.odb.root_path(), common_dir / "objects")
            assert repo.bare
            assert osp.samefile(repo.git.rev_parse("--absolute-git-dir"), git_dir)
            assert osp.samefile(repo.git.rev_parse("--git-common-dir"), common_dir)
        environment = dict(os.environ)
        environment["GIT_DIR"] = "git-file"
        environment.pop("GIT_COMMON_DIR", None)
        with cwd(root), mock.patch.dict(os.environ, environment, clear=True), Repo() as repo:
            assert osp.samefile(repo.git.rev_parse("--absolute-git-dir"), root / "git-file")
        if sys.platform.startswith("linux"):
            with Repo(root / "git-bytes") as repo:
                assert osp.samefile(repo.common_dir, root / os.fsdecode(b"common-\xff"))

    def test_repo_discovery_preserves_object_directory(self):
        root = read_only_fixture("repo.sh", "object-directory")
        object_dir = root / "objects"
        blob_hexsha = (root / "blob-id").read_text().strip()
        with cwd(root), mock.patch.dict(os.environ, {"GIT_DIR": "git", "GIT_OBJECT_DIRECTORY": "objects"}):
            repo = Repo()
        with repo:
            assert osp.samefile(repo.odb.root_path(), object_dir)
            assert repo.odb.has_object(bytes.fromhex(blob_hexsha))
            assert repo.git.cat_file("blob", blob_hexsha) == "custom object database"
            assert repo.alternates == []

    def test_repo_creation_from_different_paths(self):
        path = read_only_fixture(
            "history.sh", self.rorepo.working_dir, self.rorepo.head.commit.hexsha, "0.3.2.1", "worktree"
        )
        rw_repo = Repo(path / "repo")
        r_from_gitdir = Repo(rw_repo.git_dir)
        self.assertEqual(r_from_gitdir.git_dir, rw_repo.git_dir)
        assert r_from_gitdir.git_dir.endswith(".git")
        assert not rw_repo.git.working_dir.endswith(".git")
        self.assertEqual(r_from_gitdir.git.working_dir, rw_repo.git.working_dir)

    def test_repo_creation_pathlib(self):
        path = read_only_fixture(
            "history.sh", self.rorepo.working_dir, self.rorepo.head.commit.hexsha, "0.3.2.1", "worktree"
        )
        rw_repo = Repo(path / "repo")
        r_from_gitdir = Repo(pathlib.Path(rw_repo.git_dir))
        self.assertEqual(r_from_gitdir.git_dir, rw_repo.git_dir)

    def test_repo_creation_pathlike(self):
        path = read_only_fixture(
            "history.sh", self.rorepo.working_dir, self.rorepo.head.commit.hexsha, "0.3.2.1", "worktree"
        )
        rw_repo = Repo(path / "repo")
        r_from_gitdir = Repo(PathLikeMock(rw_repo.git_dir))
        self.assertEqual(r_from_gitdir.git_dir, rw_repo.git_dir)

    @with_rw_repo("HEAD")
    def test_description(self, rw_repo):
        txt = "Test repository"
        rw_repo.description = txt
        self.assertEqual(rw_repo.description, txt)

    def test_heads_should_return_array_of_head_objects(self):
        for head in self.rorepo.heads:
            self.assertEqual(Head, head.__class__)

    def test_heads_should_populate_head_data(self):
        for head in self.rorepo.heads:
            assert head.name
            self.assertIsInstance(head.commit, Commit)
        # END for each head

        active_branch = self.rorepo.active_branch
        self.assertIsInstance(self.rorepo.heads[active_branch.name], Head)
        self.assertEqual(self.rorepo.heads[active_branch.name], active_branch)

    def test_tree_from_revision(self):
        tree = self.rorepo.tree("0.1.6")
        self.assertEqual(len(tree.hexsha), 40)
        self.assertEqual(tree.type, "tree")
        self.assertEqual(self.rorepo.tree(tree), tree)

        # Try from an invalid revision that does not exist.
        self.assertRaises(BadName, self.rorepo.tree, "hello world")

    def test_pickleable(self):
        pickle.loads(pickle.dumps(self.rorepo))

    def test_commit_from_revision(self):
        commit = self.rorepo.commit("0.1.4")
        self.assertEqual(commit.type, "commit")
        self.assertEqual(self.rorepo.commit(commit), commit)

    def test_commit_from_tag_starting_with_at(self):
        with fixture_repo("repo.sh", "at-tag") as repo:
            commit = repo.head.commit
            self.assertEqual(repo.tags["@foo"].commit, commit)
            self.assertEqual(repo.commit("@"), commit)
            self.assertEqual(repo.commit("@foo"), commit)

    def test_commits(self):
        mc = 10
        commits = list(self.rorepo.iter_commits("0.1.6", max_count=mc))
        self.assertEqual(len(commits), mc)

        c = commits[0]
        self.assertEqual("9a4b1d4d11eee3c5362a4152216376e634bd14cf", c.hexsha)
        self.assertEqual(["c76852d0bff115720af3f27acdb084c59361e5f6"], [p.hexsha for p in c.parents])
        self.assertEqual("ce41fc29549042f1aa09cc03174896cf23f112e3", c.tree.hexsha)
        self.assertEqual("Michael Trier", c.author.name)
        self.assertEqual("mtrier@gmail.com", c.author.email)
        self.assertEqual(1232829715, c.authored_date)
        self.assertEqual(5 * 3600, c.author_tz_offset)
        self.assertEqual("Michael Trier", c.committer.name)
        self.assertEqual("mtrier@gmail.com", c.committer.email)
        self.assertEqual(1232829715, c.committed_date)
        self.assertEqual(5 * 3600, c.committer_tz_offset)
        self.assertEqual("Bumped version 0.1.6\n", c.message)

        c = commits[1]
        self.assertIsInstance(c.parents, tuple)

    def test_trees(self):
        mc = 30
        num_trees = 0
        for tree in self.rorepo.iter_trees("0.1.5", max_count=mc):
            num_trees += 1
            self.assertIsInstance(tree, Tree)
        # END for each tree
        self.assertEqual(num_trees, mc)

    def _assert_empty_repo(self, repo):
        """Test all kinds of things with an empty, freshly initialized repo.

        It should throw good errors.
        """
        # Entries should be empty.
        self.assertEqual(len([(e.path, e.stage) for e in repo.index.iter_entries()]), 0)

        # head is accessible.
        assert repo.head
        assert repo.head.ref
        assert not repo.head.is_valid()

        # We can change the head to some other ref.
        head_ref = Head.from_path(repo, Head.to_full_path("some_head"))
        assert not head_ref.is_valid()
        repo.head.ref = head_ref

        # is_dirty can handle all kwargs.
        for args in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
            assert not repo.is_dirty(*args)
        # END for each arg

        # We can add a file to the index (if we are not bare).
        if not repo.bare:
            pass
        # END test repos with working tree

    @with_rw_directory(script="repo.sh", args=("empty-repo",))
    def test_clone_from_keeps_env(self, rw_dir):
        original_repo = Repo(osp.join(rw_dir, "repo"))
        environment = {"entry1": "value", "another_entry": "10"}

        cloned = Repo.clone_from(original_repo.git_dir, osp.join(rw_dir, "clone"), env=environment)

        for key, value in environment.items():
            self.assertEqual(cloned.git.environment()[key], value)
        self.assertEqual(cloned.git.environment()["GIT_DIR"], cloned.git_dir)
        self.assertEqual(cloned.git.environment()["GIT_WORK_TREE"], cloned.working_tree_dir)

    @pytest.mark.skipif(os.name != "nt", reason="Specifically for Windows drive-rooted paths.")
    @with_rw_directory(script="repo.sh", args=("empty-repo",))
    def test_clone_from_drive_rooted_destination(self, rw_dir):
        original_repo = Repo(osp.join(rw_dir, "repo"))
        with cwd(rw_dir):
            destination = osp.join(rw_dir, "clone")
            _drive, rooted_destination = osp.splitdrive(destination)

            cloned = Repo.clone_from(original_repo.git_dir, rooted_destination)

            assert osp.samefile(cloned.working_tree_dir, destination)

    @with_rw_directory(script="repo.sh", args=("empty-repo",))
    def test_date_format(self, rw_dir):
        repo = Repo(osp.join(rw_dir, "repo"))
        # @-timestamp is the format used by git commit hooks.
        repo.index.commit("Commit messages", commit_date="@1400000000 +0000")

    @with_rw_repo("HEAD")
    def test_max_chunk_size(self, repo):

        class TestOutputStream(TestBase):
            def __init__(self, max_chunk_size):
                self.max_chunk_size = max_chunk_size

            def write(self, b):
                self.assertTrue(len(b) <= self.max_chunk_size)

        for chunk_size in [16, 128, 1024]:
            repo.git.status(output_stream=TestOutputStream(chunk_size), max_chunk_size=chunk_size)

        repo.git.log(
            n=100,
            output_stream=TestOutputStream(io.DEFAULT_BUFFER_SIZE),
            max_chunk_size=None,
        )
        repo.git.log(
            n=100,
            output_stream=TestOutputStream(io.DEFAULT_BUFFER_SIZE),
            max_chunk_size=-10,
        )
        repo.git.log(n=100, output_stream=TestOutputStream(io.DEFAULT_BUFFER_SIZE))

    def test_init(self):
        with writable_fixture("repo.sh", "empty") as temporary, cwd(temporary.path()):
            git_dir_rela = "repos/foo/bar.git"
            git_dir_abs = osp.abspath(git_dir_rela)

            # With specific path
            for path in (git_dir_rela, git_dir_abs):
                r = Repo.init(path=path, bare=True)
                self.assertIsInstance(r, Repo)
                assert r.bare is True
                assert not r.has_separate_working_tree()
                assert osp.isdir(r.git_dir)

                self._assert_empty_repo(r)

                # Test clone
                clone_path = path + "_clone"
                rc = r.clone(clone_path)
                self._assert_empty_repo(rc)

                try:
                    rmtree(clone_path)
                except OSError:
                    # When relative paths are used, the clone may actually be inside of
                    # the parent directory.
                    pass
                # END exception handling

                # Try again, this time with the absolute version.
                rc = Repo.clone_from(r.git_dir, clone_path)
                self._assert_empty_repo(rc)

                rmtree(git_dir_abs)
                try:
                    rmtree(clone_path)
                except OSError:
                    # When relative paths are used, the clone may actually be inside of
                    # the parent directory.
                    pass
                # END exception handling

            # END for each path

            os.makedirs(git_dir_rela)
            os.chdir(git_dir_rela)
            r = Repo.init(bare=False)
            assert r.bare is False
            assert not r.has_separate_working_tree()

            self._assert_empty_repo(r)

    def test_bare_property(self):
        self.rorepo.bare

    @with_rw_repo("HEAD")
    def test_daemon_export(self, rw_repo):
        orig_val = rw_repo.daemon_export
        rw_repo.daemon_export = not orig_val
        self.assertEqual(rw_repo.daemon_export, (not orig_val))
        rw_repo.daemon_export = orig_val
        self.assertEqual(rw_repo.daemon_export, orig_val)

    def test_daemon_export_without_git_dir(self):
        repo = Repo.__new__(Repo)
        repo.git_dir = None
        self.assertFalse(repo._get_daemon_export())
        repo._set_daemon_export(True)

    def test_alternates(self):
        root = read_only_fixture("repo.sh", "alternates")
        with Repo(root / "repo") as repo, Repo(root / "source") as source:
            assert repo.alternates == []
            objects = osp.join(source.common_dir, "objects")
            with repo.git.custom_environment(GIT_ALTERNATE_OBJECT_DIRECTORIES=objects):
                assert len(repo.alternates) == 1
                assert osp.samefile(repo.alternates[0], objects)
            with pytest.raises(AttributeError):
                repo.alternates = []

    def test_alternates_use_common_dir(self):
        root = read_only_fixture("repo.sh", "shared-worktree", self.rorepo.working_dir)
        with Repo(root / "shared") as repo, Repo(root / "linked") as linked:
            assert linked.alternates == repo.alternates
            assert len(linked.alternates) >= 1
            assert osp.samefile(linked.alternates[0], self.rorepo.odb.root_path())

    def test_repr(self):
        assert repr(self.rorepo).startswith("<git.repo.base.Repo ")

    def test_is_dirty_with_bare_repository(self):
        orig_value = self.rorepo._bare
        self.rorepo._bare = True
        self.assertFalse(self.rorepo.is_dirty())
        self.rorepo._bare = orig_value

    def test_is_dirty(self):
        self.rorepo._bare = False
        for index in (0, 1):
            for working_tree in (0, 1):
                for untracked_files in (0, 1):
                    assert self.rorepo.is_dirty(index, working_tree, untracked_files) in (True, False)
                # END untracked files
            # END working tree
        # END index
        orig_val = self.rorepo._bare
        self.rorepo._bare = True
        assert self.rorepo.is_dirty() is False
        self.rorepo._bare = orig_val

    def test_is_dirty_pathspec(self):
        self.rorepo._bare = False
        for index in (0, 1):
            for working_tree in (0, 1):
                for untracked_files in (0, 1):
                    assert self.rorepo.is_dirty(index, working_tree, untracked_files, path=":!foo") in (True, False)
                # END untracked files
            # END working tree
        # END index
        orig_val = self.rorepo._bare
        self.rorepo._bare = True
        assert self.rorepo.is_dirty() is False
        self.rorepo._bare = orig_val

    def test_is_dirty_with_path(self):
        for state in ("clean", "worktree", "index", "untracked"):
            with fixture_repo("repo.sh", "dirty", state) as repo:
                assert repo.is_dirty(path="git") is (state != "clean")
                assert repo.is_dirty(path="doc") is False
                if state == "index":
                    assert repo.is_dirty(index=False, path="git") is False
                if state == "untracked":
                    assert repo.is_dirty(untracked_files=True, path="doc") is True

    def test_is_dirty_with_pathlib_and_pathlike(self):
        with fixture_repo("repo.sh", "dirty", "worktree") as repo:
            assert repo.is_dirty(path=Path("git")) is True
            assert repo.is_dirty(path=PathLikeMock("git")) is True
            assert repo.is_dirty(path=Path("doc")) is False
            assert repo.is_dirty(path=PathLikeMock("doc")) is False

    def test_head(self):
        self.assertEqual(self.rorepo.head.reference.object, self.rorepo.active_branch.object)

    def test_index(self):
        index = self.rorepo.index
        self.assertIsInstance(index, IndexFile)

    def test_tag(self):
        assert self.rorepo.tag("refs/tags/0.1.5").commit

    def test_tag_to_full_tag_path(self):
        tags = ["0.1.5", "tags/0.1.5", "refs/tags/0.1.5"]
        value_errors = []
        for tag in tags:
            try:
                self.rorepo.tag(tag)
            except ValueError as valueError:
                value_errors.append(valueError.args[0])
        self.assertEqual(value_errors, [])

    def test_archive(self):
        with tempfile.NamedTemporaryFile("wb", suffix="archive-test", delete=False) as stream:
            self.rorepo.archive(stream, "0.1.6", path="doc")
            assert stream.tell()
        os.remove(stream.name)  # Do it this way so we can inspect the file on failure.

    def test_archive_rejects_unsafe_options(self):
        tdir = str(read_only_fixture("repo.sh", "empty"))
        output_marker = osp.join(tdir, "pwn")
        with self.assertRaises(UnsafeOptionError):
            self.rorepo.archive(io.BytesIO(), "0.1.6", exec=f"touch {output_marker}")
        assert not osp.exists(output_marker)
        with self.assertRaises(UnsafeOptionError):
            self.rorepo.archive(io.BytesIO(), "0.1.6", output=output_marker)
        assert not osp.exists(output_marker)
        with self.assertRaises(UnsafeOptionError):
            self.rorepo.archive(io.BytesIO(), "0.1.6", add_file=output_marker)
        with self.assertRaises(UnsafeOptionError):
            self.rorepo.archive(io.BytesIO(), "0.1.6", add_virtual_file="file:content")

    def test_archive_rejects_unsafe_remote_protocol(self):
        tdir = str(read_only_fixture("repo.sh", "empty"))
        output_marker = osp.join(tdir, "pwn")
        with self.assertRaises(UnsafeProtocolError):
            self.rorepo.archive(io.BytesIO(), "HEAD", remote=f"ext::sh -c touch% {output_marker}")
        assert not osp.exists(output_marker)

    def test_archive_preserves_positional_allow_unsafe_options(self):
        with mock.patch.object(Git, "_call_process") as git:
            self.rorepo.archive(io.BytesIO(), "HEAD", None, True, exec="git-upload-archive")
        git.assert_called_once()

    def test_archive_accepts_stringifiable_remote(self):
        class StringifiableRemote:
            def __str__(self):
                return "origin"

        with mock.patch.object(Git, "_call_process") as git:
            self.rorepo.archive(io.BytesIO(), "HEAD", remote=StringifiableRemote())
        git.assert_called_once()

    def test_archive_rejects_unsafe_falsey_remote_protocol(self):
        class FalseyRemote:
            def __bool__(self):
                return False

            def __str__(self):
                return "ext::sh -c true"

        with self.assertRaises(UnsafeProtocolError):
            self.rorepo.archive(io.BytesIO(), "HEAD", remote=FalseyRemote())

    def test_iter_commits_rejects_unsafe_revision(self):
        tdir = str(read_only_fixture("repo.sh", "empty"))
        target = osp.join(tdir, "pwn")
        with self.assertRaises(UnsafeOptionError):
            list(self.rorepo.iter_commits(f"--output={target}", max_count=1))

    def test_should_display_blame_information(self):
        original_call = Git._call_process
        git = mock.Mock(return_value=fixture("blame"))

        def blame_only(command, method, *args, **kwargs):
            if method == "blame":
                return git(method, *args, **kwargs)
            return original_call(command, method, *args, **kwargs)

        patcher = mock.patch.object(Git, "_call_process", blame_only)
        patcher.start()
        self.addCleanup(patcher.stop)
        b = self.rorepo.blame("master", "lib/git.py")
        self.assertEqual(13, len(b))
        self.assertEqual(2, len(b[0]))
        # self.assertEqual(25, reduce(lambda acc, x: acc + len(x[-1]), b))
        self.assertEqual(hash(b[0][0]), hash(b[9][0]))
        c = b[0][0]
        self.assertTrue(git.called)

        self.assertEqual("634396b2f541a9f2d58b00be1a07f0c358b999b3", c.hexsha)
        self.assertEqual("Tom Preston-Werner", c.author.name)
        self.assertEqual("tom@mojombo.com", c.author.email)
        self.assertEqual(1191997100, c.authored_date)
        self.assertEqual("Tom Preston-Werner", c.committer.name)
        self.assertEqual("tom@mojombo.com", c.committer.email)
        self.assertEqual(1191997100, c.committed_date)
        self.assertRaisesRegex(
            BadObject,
            "634396b2f541a9f2d58b00be1a07f0c358b999b3",
            lambda: c.message,
        )

        # Test the 'lines per commit' entries.
        tlist = b[0][1]
        self.assertTrue(tlist)
        self.assertTrue(isinstance(tlist[0], str))
        self.assertTrue(len(tlist) < sum(len(t) for t in tlist))  # Test for single-char bug.

        # BINARY BLAME
        git.return_value = fixture("blame_binary")
        blames = self.rorepo.blame("master", "rps")
        self.assertEqual(len(blames), 2)

    def test_blame_real(self):
        c = 0
        nml = 0  # Amount of multi-lines per blame.
        for item in self.rorepo.head.commit.tree.traverse(
            predicate=lambda i, d: i.type == "blob" and i.path.endswith(".py")
        ):
            c += 1

            for b in self.rorepo.blame(self.rorepo.head, item.path):
                nml += int(len(b[1]) > 1)
        # END for each item to traverse
        assert c, "Should have executed at least one blame command"
        assert nml, "There should at least be one blame commit that contains multiple lines"

    def test_blame_rejects_unsafe_revision(self):
        tdir = str(read_only_fixture("repo.sh", "empty"))
        output_marker = osp.join(tdir, "pwn")
        for option in ("--output", "--contents", "-S", "-wS", "--ignore-revs-file"):
            with self.assertRaises(UnsafeOptionError):
                self.rorepo.blame(f"{option}={output_marker}", "README.md")
            with self.assertRaises(UnsafeOptionError):
                list(self.rorepo.blame_incremental(f"{option}={output_marker}", "README.md"))
        assert not osp.exists(output_marker)

    def test_blame_rejects_unsafe_options(self):
        tdir = str(read_only_fixture("repo.sh", "empty"))
        output_marker = osp.join(tdir, "pwn")
        with self.assertRaises(UnsafeOptionError):
            self.rorepo.blame("HEAD", "README.md", output=output_marker)
        assert not osp.exists(output_marker)

    def test_blame_rejects_unsafe_rev_opts(self):
        tdir = str(read_only_fixture("repo.sh", "empty"))
        output_marker = osp.join(tdir, "pwn")
        with self.assertRaises(UnsafeOptionError):
            self.rorepo.blame("HEAD", "README.md", rev_opts=(f"--output={output_marker}",))
        assert not osp.exists(output_marker)

    @mock.patch.object(Git, "_call_process")
    def test_blame_incremental(self, git):
        # Loop over two fixtures, create a test fixture for 2.11.1+ syntax.
        for git_fixture in ("blame_incremental", "blame_incremental_2.11.1_plus"):
            git.return_value = fixture(git_fixture)
            blame_output = self.rorepo.blame_incremental("9debf6b0aafb6f7781ea9d1383c86939a1aacde3", "AUTHORS")
            blame_output = list(blame_output)
            self.assertEqual(len(blame_output), 5)

            # Check all outputted line numbers.
            ranges = flatten([entry.linenos for entry in blame_output])
            self.assertEqual(
                ranges,
                flatten(
                    [
                        range(2, 3),
                        range(14, 15),
                        range(1, 2),
                        range(3, 14),
                        range(15, 17),
                    ]
                ),
            )

            commits = [entry.commit.hexsha[:7] for entry in blame_output]
            self.assertEqual(commits, ["82b8902", "82b8902", "c76852d", "c76852d", "c76852d"])

            # Original filenames.
            self.assertSequenceEqual(
                [entry.orig_path for entry in blame_output],
                ["AUTHORS"] * len(blame_output),
            )

            # Original line numbers.
            orig_ranges = flatten([entry.orig_linenos for entry in blame_output])
            self.assertEqual(
                orig_ranges,
                flatten(
                    [
                        range(2, 3),
                        range(14, 15),
                        range(1, 2),
                        range(2, 13),
                        range(13, 15),
                    ]
                ),
            )

    @mock.patch.object(Git, "_call_process")
    def test_blame_complex_revision(self, git):
        git.return_value = fixture("blame_complex_revision")
        res = self.rorepo.blame("HEAD~10..HEAD", "README.md")
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res[0][1]), 83, "Unexpected amount of parsed blame lines")

    @mock.patch.object(Git, "_call_process_safe")
    def test_blame_accepts_rev_opts(self, git):
        expected_args = ["blame", "HEAD", "-M", "-C", "-C", "--no-textconv", "--", "README.md"]
        boilerplate_kwargs = {"p": True, "stdout_as_string": False}
        git.return_value = b""
        self.rorepo.blame("HEAD", "README.md", rev_opts=["-M", "-C", "-C"])
        git.assert_called_once_with(*expected_args, **boilerplate_kwargs)

    def test_blame_content_with_carriage_returns(self):
        # A lone CR inside a line of content, followed by text shaped like blame
        # porcelain headers for a forged commit and author.
        forged = "\r".join(
            [
                "ok",
                "0" * 40 + " 2 2 1",
                "author Forged Author",
                "author-mail <forged@example.com>",
                "author-time 1000000000",
                "committer Forged Author",
                "committer-mail <forged@example.com>",
                "committer-time 1000000000",
                "\tforged()",
            ]
        )
        with fixture_repo("repo.sh", "blame-carriage-returns") as repo:
            blames = repo.blame("HEAD", "file.txt")
            self.assertEqual(len(blames), 1)
            self.assertEqual(blames[0][0], repo.head.commit)
            self.assertEqual(blames[0][0].author.name, "GitPython Tests")
            self.assertEqual(blames[0][1], ["first", forged])

    def test_untracked_files(self):
        for command in ("index", "git"):
            with fixture_repo("repo.sh", "untracked", write=True) as repo:
                files = ["test _myfile", "test_other_file", "_çava verböten", "çava-----verböten"]
                assert sorted(repo.untracked_files) == sorted(files)
                repo_add = repo.index.add if command == "index" else repo.git.add
                repo_add(repo.untracked_files)
                assert repo.untracked_files == []
        # END for each run

    def test_untracked_files_with_unquoted_unicode_and_escapes(self):
        paths = {"plain.txt", "caf\u00e9.txt", "caf\u00e9\x7f.txt", " leading.txt"}
        for quote_path in ("true", "false"):
            with self.subTest(quote_path=quote_path), fixture_repo("repo.sh", "untracked-unicode", quote_path) as repo:
                baseline = repo.git.status("--porcelain=v1", "-z", "--untracked-files=all", stdout_as_string=False)
                assert set(baseline.rstrip(b"\0").split(b"\0")) == {b"?? " + path.encode("utf-8") for path in paths}
                assert set(repo.untracked_files) == paths
                assert repo.is_dirty(untracked_files=True)

    def test_config_reader(self):
        reader = self.rorepo.config_reader()  # All config files.
        assert reader.read_only
        reader = self.rorepo.config_reader("repository")  # Single config file.
        assert reader.read_only

    @with_rw_repo("HEAD")
    def test_config_writer(self, rw_repo):
        for config_level in rw_repo.config_level:
            try:
                with rw_repo.config_writer(config_level) as writer:
                    self.assertFalse(writer.read_only)
            except OSError:
                # It's okay not to get a writer for some configuration files if we
                # have no permissions.
                pass

    def test_config_level_paths(self):
        for config_level in self.rorepo.config_level:
            assert self.rorepo._get_config_path(config_level)

    @with_rw_repo("HEAD")
    def test_creation_deletion(self, rw_repo):
        # Just a very quick test to assure it generally works. There are specialized
        # cases in the test_refs module.
        head = rw_repo.create_head("new_head", "HEAD~1")
        rw_repo.delete_head(head)

        try:
            tag = rw_repo.create_tag("new_tag", "HEAD~2")
        finally:
            rw_repo.delete_tag(tag)
        with rw_repo.config_writer():
            pass
        try:
            remote = rw_repo.create_remote("new_remote", "git@server:repo.git")
        finally:
            rw_repo.delete_remote(remote)

    def test_comparison_and_hash(self):
        # This is only a preliminary test, more testing done in test_index.
        self.assertEqual(self.rorepo, self.rorepo)
        self.assertFalse(self.rorepo != self.rorepo)
        self.assertEqual(len({self.rorepo, self.rorepo}), 1)

    def test_git_cmd(self):
        # Test CatFileContentStream, just to be very sure we have no fencepost errors.
        # The last \n is the terminating newline that it expects.
        l1 = b"0123456789\n"
        l2 = b"abcdefghijklmnopqrstxy\n"
        l3 = b"z\n"
        d = l1 + l2 + l3 + b"\n"

        l1p = l1[:5]

        # Full size.
        # Size is without terminating newline.
        def mkfull():
            return Git.CatFileContentStream(len(d) - 1, BytesIO(d))

        ts = 5

        def mktiny():
            return Git.CatFileContentStream(ts, BytesIO(d))

        # readlines no limit
        s = mkfull()
        lines = s.readlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[-1].endswith(b"\n"), lines[-1])
        self.assertEqual(s._stream.tell(), len(d))  # Must have scrubbed to the end.

        # realines line limit
        s = mkfull()
        lines = s.readlines(5)
        self.assertEqual(len(lines), 1)

        # readlines on tiny sections
        s = mktiny()
        lines = s.readlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], l1p)
        self.assertEqual(s._stream.tell(), ts + 1)

        # readline no limit
        s = mkfull()
        self.assertEqual(s.readline(), l1)
        self.assertEqual(s.readline(), l2)
        self.assertEqual(s.readline(), l3)
        self.assertEqual(s.readline(), b"")
        self.assertEqual(s._stream.tell(), len(d))

        # readline limit
        s = mkfull()
        self.assertEqual(s.readline(5), l1p)
        self.assertEqual(s.readline(), l1[5:])

        # readline on tiny section
        s = mktiny()
        self.assertEqual(s.readline(), l1p)
        self.assertEqual(s.readline(), b"")
        self.assertEqual(s._stream.tell(), ts + 1)

        # read no limit
        s = mkfull()
        self.assertEqual(s.read(), d[:-1])
        self.assertEqual(s.read(), b"")
        self.assertEqual(s._stream.tell(), len(d))

        # read limit
        s = mkfull()
        self.assertEqual(s.read(5), l1p)
        self.assertEqual(s.read(6), l1[5:])
        self.assertEqual(s._stream.tell(), 5 + 6)  # It's not yet done.

        # read tiny
        s = mktiny()
        self.assertEqual(s.read(2), l1[:2])
        self.assertEqual(s._stream.tell(), 2)
        self.assertEqual(s.read(), l1[2:ts])
        self.assertEqual(s._stream.tell(), ts + 1)

    def _assert_rev_parse_types(self, name, rev_obj):
        rev_parse = self.rorepo.rev_parse

        if rev_obj.type == "tag":
            rev_obj = rev_obj.object

        # Tree and blob type.
        obj = rev_parse(name + "^{tree}")
        self.assertEqual(obj, rev_obj.tree)

        obj = rev_parse(name + ":CHANGES")
        self.assertEqual(obj.type, "blob")
        self.assertEqual(obj.path, "CHANGES")
        self.assertEqual(rev_obj.tree["CHANGES"], obj)

    def _assert_rev_parse(self, name):
        """tries multiple different rev-parse syntaxes with the given name
        :return: parsed object"""
        rev_parse = self.rorepo.rev_parse
        orig_obj = rev_parse(name)
        if orig_obj.type == "tag":
            obj = orig_obj.object
        else:
            obj = orig_obj
        # END deref tags by default

        # Try history
        rev = name + "~"
        obj2 = rev_parse(rev)
        self.assertEqual(obj2, obj.parents[0])
        self._assert_rev_parse_types(rev, obj2)

        # History with number
        ni = 11
        history = [obj.parents[0]]
        for _ in range(ni):
            history.append(history[-1].parents[0])
        # END get given amount of commits

        for pn in range(11):
            rev = name + "~%i" % (pn + 1)
            obj2 = rev_parse(rev)
            self.assertEqual(obj2, history[pn])
            self._assert_rev_parse_types(rev, obj2)
        # END history check

        # Parent (default)
        rev = name + "^"
        obj2 = rev_parse(rev)
        self.assertEqual(obj2, obj.parents[0])
        self._assert_rev_parse_types(rev, obj2)

        # Parent with number
        for pn, parent in enumerate(obj.parents):
            rev = name + "^%i" % (pn + 1)
            self.assertEqual(rev_parse(rev), parent)
            self._assert_rev_parse_types(rev, parent)
        # END for each parent

        return orig_obj

    def test_rw_rev_parse(self):
        with fixture_repo("repo.sh", "hex-branch") as repo:
            ahead = repo.heads.aaaaaaaa
            assert repo.rev_parse(str(ahead)) == ahead.commit

    def test_rev_parse(self):
        rev_parse = self.rorepo.rev_parse

        # Try special case: This one failed at some point, make sure its fixed.
        self.assertEqual(rev_parse("33ebe").hexsha, "33ebe7acec14b25c5f84f35a664803fcab2f7781")

        # Start from reference.
        num_resolved = 0

        for ref_no, ref in enumerate(Reference.iter_items(self.rorepo)):
            path_tokens = ref.path.split("/")
            for pt in range(len(path_tokens)):
                path_section = "/".join(path_tokens[-(pt + 1) :])
                try:
                    obj = self._assert_rev_parse(path_section)
                    self.assertEqual(obj.type, ref.object.type)
                    num_resolved += 1
                except (BadName, BadObject):
                    print("failed on %s" % path_section)
                    # This is fine if we have something like 112, which belongs to
                    # remotes/rname/merge-requests/112.
                # END exception handling
            # END for each token
            if ref_no == 3 - 1:
                break
        # END for each reference
        assert num_resolved

        # It works with tags!
        tag = self._assert_rev_parse("0.1.4")
        self.assertEqual(tag.type, "tag")

        # try full sha directly (including type conversion).
        self.assertEqual(tag.object, rev_parse(tag.object.hexsha))
        self._assert_rev_parse_types(tag.object.hexsha, tag.object)

        # Multiple tree types result in the same tree: HEAD^{tree}^{tree}:CHANGES
        rev = "0.1.4^{tree}^{tree}"
        self.assertEqual(rev_parse(rev), tag.object.tree)
        self.assertEqual(rev_parse(rev + ":CHANGES"), tag.object.tree["CHANGES"])

        # Try to get parents from first revision - it should fail as no such revision
        # exists.
        first_rev = "33ebe7acec14b25c5f84f35a664803fcab2f7781"
        commit = rev_parse(first_rev)
        self.assertEqual(len(commit.parents), 0)
        self.assertEqual(commit.hexsha, first_rev)
        self.assertRaises(BadName, rev_parse, first_rev + "~")
        self.assertRaises(BadName, rev_parse, first_rev + "^")

        # Short SHA1.
        commit2 = rev_parse(first_rev[:20])
        self.assertEqual(commit2, commit)
        commit2 = rev_parse(first_rev[:5])
        self.assertEqual(commit2, commit)

        # TODO: Dereference tag into a blob 0.1.7^{blob} - quite a special one.
        # Needs a tag which points to a blob.

        # ref^0 returns commit being pointed to, same with ref~0, ^{}, and ^{commit}
        tag = rev_parse("0.1.4")
        for token in ("~0", "^0", "^{}", "^{commit}"):
            self.assertEqual(tag.object, rev_parse("0.1.4%s" % token))
        # END handle multiple tokens

        # Try partial parsing.
        max_items = 40
        for i, binsha in enumerate(self.rorepo.odb.sha_iter()):
            self.assertEqual(
                rev_parse(bin_to_hex(binsha)[: 8 - (i % 2)].decode("ascii")).binsha,
                binsha,
            )
            if i > max_items:
                # This is rather slow currently, as rev_parse returns an object that
                # requires accessing packs, so it has some additional overhead.
                break
        # END for each binsha in repo

        # Missing closing brace: commit^{tree
        self.assertRaises(BadName, rev_parse, "0.1.4^{tree")

        # Missing starting brace.
        self.assertRaises(BadName, rev_parse, "0.1.4^tree}")

        # REVLOG
        #######
        head = self.rorepo.head

        # Need to specify a ref when using the @ syntax.
        self.assertRaises(BadName, rev_parse, "%s@{0}" % head.commit.hexsha)

        # Uses HEAD.ref by default.
        self.assertEqual(rev_parse("@{0}"), head.commit)
        if not head.is_detached:
            refspec = "%s@{0}" % head.ref.name
            self.assertEqual(rev_parse(refspec), head.ref.commit)
            # All additional specs work as well.
            self.assertEqual(rev_parse(refspec + "^{tree}"), head.commit.tree)
            self.assertEqual(rev_parse(refspec + ":CHANGES").type, "blob")
        # END operate on non-detached head

        # Position doesn't exist.
        self.assertRaises(GitCommandError, rev_parse, "@{10000}")

        # Date-based reflog selectors now follow native Git semantics.
        self.assertEqual(rev_parse("@{1 week ago}").hexsha, self.rorepo.git.rev_parse("@{1 week ago}"))

        # The previous position, if this checkout has enough reflog history.
        try:
            previous = rev_parse("@{1}")
        except GitCommandError:
            pass
        else:
            self.assertNotEqual(previous, head.commit)

    def test_repo_odbtype(self):
        target_type = GitCmdObjectDB
        self.assertIsInstance(self.rorepo.odb, target_type)

    def test_submodules(self):
        path = read_only_fixture(
            "history.sh",
            self.rorepo.working_dir,
            self.rorepo.head.commit.hexsha,
            "c15a6e1923a14bc760851913858a3942a4193cdb",
            "bare",
        )
        rwrepo = Repo(path / "repo")
        self.assertEqual(len(rwrepo.submodules), 1)
        self.assertIsInstance(rwrepo.submodule("gitdb"), Submodule)
        self.assertRaises(ValueError, rwrepo.submodule, "doesn't exist")

    @with_rw_repo("HEAD", bare=False)
    def test_submodule_update(self, rwrepo):
        # Fails in bare mode.
        rwrepo._bare = True
        self.assertRaises(InvalidGitRepositoryError, rwrepo.submodule_update)
        rwrepo._bare = False

        # Test submodule creation.
        sm = rwrepo.create_submodule(
            "my_new_sub",
            "some_path",
            self._small_repo_url(),
        )
        self.assertIsInstance(sm, Submodule)

        # NOTE: The rest of this functionality is tested in test_submodule.

    def test_git_file(self):
        for kind in ("relative", "absolute"):
            root = read_only_fixture("repo.sh", "relocated-git-dir", kind)
            with Repo(root / "repo") as repo:
                self.assertEqual(osp.abspath(repo.git_dir), str(root / "repo" / ".real"))

    def test_file_handle_leaks(self):
        def last_commit(repo, rev, path):
            commit = next(repo.iter_commits(rev, path, max_count=1))
            commit.tree[path]

        # This is based on this comment:
        # https://github.com/gitpython-developers/GitPython/issues/60#issuecomment-23558741
        # And we expect to set max handles to a low value, like 64.
        # You should set ulimit -n X. See .travis.yml.
        # The loops below would easily create 500 handles if these would leak
        # (4 pipes + multiple mapped files).
        for _ in range(64):
            for repo_type in (GitCmdObjectDB,):
                repo = Repo(self.rorepo.working_tree_dir, odbt=repo_type)
                last_commit(repo, "HEAD", "test/test_base.py")
            # END for each repository type
        # END for each iteration

    def test_remote_method(self):
        self.assertRaises(ValueError, self.rorepo.remote, "foo-blue")
        self.assertIsInstance(self.rorepo.remote(name="origin"), Remote)

    @with_rw_directory(script="repo.sh", args=("root-repo",))
    def test_empty_repo(self, rw_dir):
        """Assure we can handle empty repositories"""
        r = Repo(rw_dir)
        # It's ok not to be able to iterate a commit, as there is none.
        self.assertRaises(ValueError, r.iter_commits)
        self.assertEqual(r.active_branch.name, "master")
        assert not r.active_branch.is_valid(), "Branch is yet to be born"

        # Actually, when trying to create a new branch without a commit, git itself
        # fails. We should, however, not fail ungracefully.
        self.assertRaises(BadName, r.create_head, "foo")
        self.assertRaises(BadName, r.create_head, "master")
        # It's expected to not be able to access a tree
        self.assertRaises(ValueError, r.tree)

        new_file_path = osp.join(rw_dir, "new_file.ext")
        r.index.add([new_file_path])
        r.index.commit("initial commit\nBAD MESSAGE 1\n")

        # Now a branch should be creatable.
        nb = r.create_head("foo")
        assert nb.is_valid()

        with open(new_file_path, "w") as f:
            f.write("Line 1\n")

        r.index.add([new_file_path])
        r.index.commit("add line 1\nBAD MESSAGE 2\n")

        with open("%s/.git/logs/refs/heads/master" % (rw_dir,), "r") as f:
            contents = f.read()

        assert "BAD MESSAGE" not in contents, "log is corrupt"

    @with_rw_directory(script="repo.sh", args=("root-repo",))
    def test_active_branch_raises_value_error_when_head_ref_is_invalid(self, rw_dir):
        repo = Repo(rw_dir)
        with open(osp.join(rw_dir, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/.invalid\n")

        self.assertRaisesRegex(
            ValueError,
            r"Invalid reference 'refs/heads/\.invalid'",
            lambda: repo.active_branch,
        )

    def test_empty_repo_reftable_active_branch(self):
        with fixture_repo("repo.sh", "reftable", "empty") as repo:
            self.assertEqual(repo.head.reference.name, repo.git.symbolic_ref("--short", "HEAD"))
            self.assertEqual(repo.active_branch, repo.head.reference)
            self.assertFalse(repo.active_branch.is_valid())

    def test_reftable_repo_exposes_native_references(self):
        with fixture_repo("repo.sh", "reftable", "commit") as repo:
            expected_head = (Path(repo.working_dir).parent / "head-id").read_text().strip()
            assert repo.git.rev_parse("HEAD") == expected_head
            assert repo.head.reference.name == repo.git.symbolic_ref("--short", "HEAD")
            assert repo.head.commit.hexsha == expected_head
            assert repo.heads

    def test_active_branch_raises_type_error_when_head_is_detached(self):
        with fixture_repo("repo.sh", "detached") as repo:
            self.assertRaisesRegex(TypeError, "detached symbolic reference", lambda: repo.active_branch)

    def test_merge_base(self):
        repo = self.rorepo
        c1 = "f6aa8d1"
        c2 = repo.commit("d46e3fe")
        c3 = "763ef75"
        self.assertRaises(ValueError, repo.merge_base)
        self.assertRaises(ValueError, repo.merge_base, "foo")

        # Two commit merge-base.
        res = repo.merge_base(c1, c2)
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 1)
        self.assertIsInstance(res[0], Commit)
        self.assertTrue(res[0].hexsha.startswith("3936084"))

        for kw in ("a", "all"):
            res = repo.merge_base(c1, c2, c3, **{kw: True})
            self.assertIsInstance(res, list)
            self.assertEqual(len(res), 1)
        # END for each keyword signalling all merge-bases to be returned

        # Test for no merge base - can't do as we have.
        self.assertRaises(GitCommandError, repo.merge_base, c1, "ffffff")

    def test_is_ancestor(self):
        git = self.rorepo.git
        if git.version_info[:3] < (1, 8, 0):
            raise RuntimeError("git merge-base --is-ancestor feature unsupported (test needs git 1.8.0 or later)")

        repo = self.rorepo
        c1 = "f6aa8d1"
        c2 = "763ef75"
        self.assertTrue(repo.is_ancestor(c1, c1))
        self.assertTrue(repo.is_ancestor("HEAD", "HEAD"))
        self.assertTrue(repo.is_ancestor(c1, c2))
        self.assertTrue(repo.is_ancestor(c1, "HEAD"))
        self.assertFalse(repo.is_ancestor(c2, c1))
        self.assertFalse(repo.is_ancestor("HEAD", c1))
        for i, j in itertools.permutations([c1, "ffffff", ""], r=2):
            self.assertRaises(GitCommandError, repo.is_ancestor, i, j)

    def test_is_valid_object(self):
        repo = self.rorepo
        commit_sha = "f6aa8d1"
        blob_sha = "1fbe3e4375"
        tree_sha = "960b40fe36"
        tag_sha = "42c2f60c43"

        # Check for valid objects.
        self.assertTrue(repo.is_valid_object(commit_sha))
        self.assertTrue(repo.is_valid_object(blob_sha))
        self.assertTrue(repo.is_valid_object(tree_sha))
        self.assertTrue(repo.is_valid_object(tag_sha))

        # Check for valid objects of specific type.
        self.assertTrue(repo.is_valid_object(commit_sha, "commit"))
        self.assertTrue(repo.is_valid_object(blob_sha, "blob"))
        self.assertTrue(repo.is_valid_object(tree_sha, "tree"))
        self.assertTrue(repo.is_valid_object(tag_sha, "tag"))

        # Check for invalid objects.
        self.assertFalse(repo.is_valid_object(b"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", "blob"))

        # Check for invalid objects of specific type.
        self.assertFalse(repo.is_valid_object(commit_sha, "blob"))
        self.assertFalse(repo.is_valid_object(blob_sha, "commit"))
        self.assertFalse(repo.is_valid_object(tree_sha, "commit"))
        self.assertFalse(repo.is_valid_object(tag_sha, "commit"))

    def test_git_work_tree_dotgit(self, use_relative_paths=False):
        root = read_only_fixture("repo.sh", "worktree", self.rorepo.working_dir, str(use_relative_paths))
        with Repo(root / "worktree_repo") as repo:
            self.assertIsInstance(repo, Repo)
            self.assertIsInstance(repo.head.commit, Object)
            self.assertIsInstance(repo.remotes.origin, Remote)
            self.assertIsInstance(repo.heads["aaaaaaaa"], Head)

    def test_git_work_tree_from_bare_repo(self):
        root = read_only_fixture("repo.sh", "bare-worktree", self.rorepo.working_dir)
        worktree = root / "worktree_repo"
        with Repo(worktree) as repo:
            assert Git(worktree).rev_parse("--is-bare-repository") == "false"
            assert not repo.bare
            assert osp.samefile(repo.working_tree_dir, worktree)
            subdir = worktree / "git" / "repo"
            with Repo(subdir, search_parent_directories=True) as sub_repo:
                assert not sub_repo.bare
                assert osp.samefile(sub_repo.working_dir, worktree)
                expected = repo.git.log("-n", "1", "--format=%H", "--", "git/repo")
                assert sub_repo.git.log("-n", "1", "--format=%H", "--", str(subdir)) == expected

    def test_git_work_tree_dotgit_relative(self):
        """Check that we find .git as a worktree file containing a relative path
        and find the worktree based on it."""
        if Git().version_info[:3] < (2, 48, 0):
            pytest.skip("relative worktree feature unsupported, needs git 2.48.0 or later")
        # this class inherits from TestCase so we can't use pytest.mark.parametrize on
        # test_git_work_tree_dotgit; delegate instead
        self.test_git_work_tree_dotgit(use_relative_paths=True)

    @pytest.mark.skipif(os.name != "nt", reason="Specifically for Windows drive-rooted paths.")
    def test_linked_worktree_drive_rooted_gitdir_file(self):
        root = read_only_fixture("repo.sh", "drive-rooted-worktree", self.rorepo.working_dir)
        with cwd(root), Repo(root / "worktree_repo") as linked:
            with Repo(linked.git_dir) as reopened:
                assert osp.samefile(reopened.working_tree_dir, root / "worktree_repo")

    def test_git_work_tree_env(self):
        root = read_only_fixture("repo.sh", "worktree-environment", self.rorepo.working_dir)
        repo_dir = str(root / "master_repo")
        git_dir = str(root / "master_repo" / "gitdir" / "git")
        with mock.patch.dict(os.environ, {"GIT_DIR": git_dir, "GIT_WORK_TREE": repo_dir}), Repo() as repo:
            self.assertEqual(repo.working_tree_dir, repo_dir)
            self.assertEqual(repo.working_dir, repo_dir)

    def test_git_work_tree_env_in_linked_worktree(self):
        root = read_only_fixture("repo.sh", "worktree", self.rorepo.working_dir, "False")
        worktree = root / "worktree_repo"
        git_dir = Git(worktree).rev_parse("--git-dir")
        patched_env = dict(os.environ)
        patched_env["GIT_DIR"] = git_dir
        patched_env.pop("GIT_WORK_TREE", None)
        patched_env.pop("GIT_COMMON_DIR", None)
        with mock.patch.dict(os.environ, patched_env, clear=True), cwd(worktree):
            with Repo(os.getcwd()) as explicit, Repo() as autodiscovered:
                self.assertTrue(osp.samefile(explicit.working_tree_dir, worktree))
                self.assertTrue(osp.samefile(autodiscovered.working_tree_dir, worktree))
                self.assertTrue(osp.samefile(autodiscovered.working_tree_dir, explicit.working_tree_dir))

    def test_rebasing(self):
        with fixture_repo("repo.sh", "rebase", "clean") as repo:
            self.assertEqual(repo.currently_rebasing_on(), None)
        with fixture_repo("repo.sh", "rebase", "conflict") as repo:
            spanish = repo.commit((Path(repo.working_dir).parent / "spanish-id").read_text().strip())
            self.assertEqual(repo.currently_rebasing_on(), spanish)

    def test_do_not_strip_newline_in_stdout(self):
        with fixture_repo("repo.sh", "hello") as repo:
            self.assertEqual(repo.git.show("HEAD:hello.txt", strip_newline_in_stdout=False), "hello\n")

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason=R"fatal: could not create leading directories of '--upload-pack=touch C:\Users\ek\AppData\Local\Temp\tmpnantqizc\pwn': Invalid argument",  # noqa: E501
        raises=GitCommandError,
    )
    @with_rw_repo("HEAD")
    def test_clone_command_injection(self, rw_repo):
        with writable_fixture("repo.sh", "empty") as temporary:
            tmp_dir = temporary.path()
            unexpected_file = tmp_dir / "pwn"
            assert not unexpected_file.exists()

            payload = f"--upload-pack=touch {unexpected_file}"
            rw_repo.clone(payload)

            assert not unexpected_file.exists()
            # A repo was cloned with the payload as name.
            assert pathlib.Path(payload).exists()

    @with_rw_repo("HEAD")
    def test_clone_from_command_injection(self, rw_repo):
        with writable_fixture("repo.sh", "empty-repo") as temporary, Repo(temporary.path() / "repo") as temp_repo:
            tmp_dir = temporary.path()
            unexpected_file = tmp_dir / "pwn"

            assert not unexpected_file.exists()
            payload = f"--upload-pack=touch {unexpected_file}"
            with self.assertRaises(GitCommandError):
                rw_repo.clone_from(payload, temp_repo.common_dir)

            assert not unexpected_file.exists()

    def test_ignored_items_reported(self):
        with fixture_repo("repo.sh", "ignore") as repo:
            assert repo.ignored(["included_file.txt", "included_dir/file.txt"]) == []
            assert repo.ignored(["ignored_file.txt"]) == ["ignored_file.txt"]
            assert repo.ignored(["included_file.txt", "ignored_file.txt"]) == ["ignored_file.txt"]
            assert repo.ignored(
                ["included_file.txt", "ignored_file.txt", "included_dir/file.txt", "ignored_dir/file.txt"]
            ) == [
                "ignored_file.txt",
                "ignored_dir/file.txt",
            ]

    def test_ignored_items_reported_verbatim(self):
        with fixture_repo("repo.sh", "ignore-verbatim") as repo:
            paths = ["donn\u00e9es.env", 'q"uote.env', "tab\t.env", "nl\nx.env"]
            assert repo.ignored(["keep.txt", *paths]) == paths

    def test_ignored_raises_error_w_symlink(self):
        from gix import testtools

        root = read_only_fixture("repo.sh", "ignore-symlink")
        if not testtools.fixture_has_symlinks(root):
            pytest.skip("fixture filesystem cannot create symlinks")
        with Repo(root / "repo") as repo:
            with pytest.raises(GitCommandError):
                repo.ignored(root / "symlink/file.txt")


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
@pytest.mark.parametrize("bare", [False, True])
@pytest.mark.parametrize(
    "dirname",
    [
        "repo with spaces",
        pytest.param(
            "repo\nwith\nnewlines",
            marks=pytest.mark.skipif(sys.platform == "win32", reason="Windows paths cannot contain newlines"),
        ),
    ],
)
def test_repo_batches_cli_metadata_queries(monkeypatch, object_format, ref_format, bare, dirname):
    from git import _backend

    monkeypatch.setattr(_backend, "gix", None)
    with fixture_repo("repo.sh", "metadata", object_format, ref_format, str(bare), dirname, subdir=dirname) as original:
        with mock.patch.object(Git, "execute", autospec=True, side_effect=Git.execute) as execute:
            with Repo(original.git_dir) as reopened:
                assert reopened.ref_format == ref_format
                assert reopened.object_format == object_format
                assert reopened.bare == bare
                assert reopened.common_dir == original.common_dir
                assert reopened.git_dir == original.git_dir
                assert reopened.working_tree_dir == original.working_tree_dir

        metadata_options = {"--show-ref-format", "--show-object-format", "--is-bare-repository", "--git-common-dir"}
        metadata_commands = [
            call.args[1] for call in execute.call_args_list if metadata_options.intersection(call.args[1])
        ]
        assert len(metadata_commands) == 1
        assert metadata_options.issubset(metadata_commands[0])


@pytest.mark.parametrize("allow_unsafe_options", (False, True))
@pytest.mark.parametrize(
    "kwargs",
    (
        {"rem": "ext::helper"},
        {"re": "ext::helper"},
        {"remo": "ext::helper"},
        {"remot": "ext::helper"},
        {"remote": ["https://example.com/repo", "ext::helper"]},
        {"remote": (None, False, "ext::helper")},
        {"remote=ext::helper": True},
        {"r=ext::helper": True},
        {"remote": "ext://helper"},
    ),
)
def test_archive_protocol_guard_checks_emitted_remote_options(kwargs, allow_unsafe_options):
    with fixture_repo("repo.sh", "empty-repo") as repo, mock.patch.object(Git, "execute") as execute:
        with pytest.raises(UnsafeProtocolError):
            repo.archive(BytesIO(), "HEAD", allow_unsafe_options=allow_unsafe_options, **kwargs)
        execute.assert_not_called()


def test_archive_preserves_safe_repeated_remote_options():
    urls = ["https://[::1]/repo.git", "ssh://git@[2001:db8::1]/repo.git"]
    with fixture_repo("repo.sh", "empty-repo") as repo:
        repo.git.version_info
        with mock.patch.object(Git, "execute") as execute:
            output = BytesIO()
            repo.archive(output, "HEAD", rem=urls)
            execute.assert_called_once()
            command = execute.call_args.args[0]
            assert command[command.index("archive") :] == ["archive", *(f"--rem={url}" for url in urls), "--", "HEAD"]
            assert command[:3] == [Git.GIT_PYTHON_GIT_EXECUTABLE, "--no-pager", "--no-optional-locks"]
            assert execute.call_args.kwargs["output_stream"] is output
            assert execute.call_args.kwargs["shell"] is False


def test_archive_protocol_and_option_opt_ins_are_independent():
    with fixture_repo("repo.sh", "empty-repo") as repo:
        repo.git.version_info
        with mock.patch.object(Git, "execute") as execute:
            with pytest.raises(UnsafeOptionError):
                repo.archive(BytesIO(), "HEAD", rem=["ext::helper"], exec="helper", allow_unsafe_protocols=True)
            execute.assert_not_called()

            output = BytesIO()
            repo.archive(
                output,
                "HEAD",
                rem=["ext::helper"],
                exec="helper",
                allow_unsafe_options=True,
                allow_unsafe_protocols=True,
            )
            execute.assert_called_once()
            command = execute.call_args.args[0]
            assert command[command.index("archive") :] == [
                "archive",
                "--rem=ext::helper",
                "--exec=helper",
                "--",
                "HEAD",
            ]
            assert command[:3] == [Git.GIT_PYTHON_GIT_EXECUTABLE, "--no-pager", "--no-optional-locks"]
            assert execute.call_args.kwargs["output_stream"] is output
            assert execute.call_args.kwargs["shell"] is False
