# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import gc
import glob
import io
from io import BytesIO
import itertools
import os
import os.path as osp
import pathlib
import pickle
import sys
import tempfile
from unittest import mock, skip

import pytest

from git import (
    BadName,
    Commit,
    Git,
    GitCmdObjectDB,
    GitCommandError,
    GitDB,
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
from git.repo.fun import touch
from git.util import bin_to_hex, cwd, cygpath, join_path_native, rmfile, rmtree

from test.lib import TestBase, fixture, with_rw_directory, with_rw_repo


def iter_flatten(lol):
    for items in lol:
        for item in items:
            yield item


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
        # Ideally this tests a directory that is outside of any repository. In the rare
        # case tempfile.gettempdir() is inside a repo, this still passes, but tests the
        # same scenario as test_new_should_raise_on_invalid_repo_location_within_repo.
        with tempfile.TemporaryDirectory() as tdir:
            self.assertRaises(InvalidGitRepositoryError, Repo, tdir)

    @with_rw_directory
    def test_new_should_raise_on_invalid_repo_location_within_repo(self, rw_dir):
        repo_dir = osp.join(rw_dir, "repo")
        Repo.init(repo_dir)
        subdir = osp.join(repo_dir, "subdir")
        os.mkdir(subdir)
        self.assertRaises(InvalidGitRepositoryError, Repo, subdir)

    def test_new_should_raise_on_non_existent_path(self):
        with tempfile.TemporaryDirectory() as tdir:
            nonexistent = osp.join(tdir, "foobar")
            self.assertRaises(NoSuchPathError, Repo, nonexistent)

    @with_rw_repo("0.3.2.1")
    def test_repo_creation_from_different_paths(self, rw_repo):
        r_from_gitdir = Repo(rw_repo.git_dir)
        self.assertEqual(r_from_gitdir.git_dir, rw_repo.git_dir)
        assert r_from_gitdir.git_dir.endswith(".git")
        assert not rw_repo.git.working_dir.endswith(".git")
        self.assertEqual(r_from_gitdir.git.working_dir, rw_repo.git.working_dir)

    @with_rw_repo("0.3.2.1")
    def test_repo_creation_pathlib(self, rw_repo):
        r_from_gitdir = Repo(pathlib.Path(rw_repo.git_dir))
        self.assertEqual(r_from_gitdir.git_dir, rw_repo.git_dir)

    def test_description(self):
        txt = "Test repository"
        self.rorepo.description = txt
        self.assertEqual(self.rorepo.description, txt)

    def test_heads_should_return_array_of_head_objects(self):
        for head in self.rorepo.heads:
            self.assertEqual(Head, head.__class__)

    def test_heads_should_populate_head_data(self):
        for head in self.rorepo.heads:
            assert head.name
            self.assertIsInstance(head.commit, Commit)
        # END for each head

        self.assertIsInstance(self.rorepo.heads.master, Head)
        self.assertIsInstance(self.rorepo.heads["master"], Head)

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
        self.assertEqual(len(repo.index.entries), 0)

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

    @with_rw_directory
    def test_clone_from_keeps_env(self, rw_dir):
        original_repo = Repo.init(osp.join(rw_dir, "repo"))
        environment = {"entry1": "value", "another_entry": "10"}

        cloned = Repo.clone_from(original_repo.git_dir, osp.join(rw_dir, "clone"), env=environment)

        self.assertEqual(environment, cloned.git.environment())

    @with_rw_directory
    def test_date_format(self, rw_dir):
        repo = Repo.init(osp.join(rw_dir, "repo"))
        # @-timestamp is the format used by git commit hooks.
        repo.index.commit("Commit messages", commit_date="@1400000000 +0000")

    @with_rw_directory
    def test_clone_from_pathlib(self, rw_dir):
        original_repo = Repo.init(osp.join(rw_dir, "repo"))

        Repo.clone_from(original_repo.git_dir, pathlib.Path(rw_dir) / "clone_pathlib")

    @with_rw_directory
    def test_clone_from_pathlib_withConfig(self, rw_dir):
        original_repo = Repo.init(osp.join(rw_dir, "repo"))

        cloned = Repo.clone_from(
            original_repo.git_dir,
            pathlib.Path(rw_dir) / "clone_pathlib_withConfig",
            multi_options=[
                "--recurse-submodules=repo",
                "--config core.filemode=false",
                "--config submodule.repo.update=checkout",
                "--config filter.lfs.clean='git-lfs clean -- %f'",
            ],
            allow_unsafe_options=True,
        )

        self.assertEqual(cloned.config_reader().get_value("submodule", "active"), "repo")
        self.assertEqual(cloned.config_reader().get_value("core", "filemode"), False)
        self.assertEqual(cloned.config_reader().get_value('submodule "repo"', "update"), "checkout")
        self.assertEqual(
            cloned.config_reader().get_value('filter "lfs"', "clean"),
            "git-lfs clean -- %f",
        )

    def test_clone_from_with_path_contains_unicode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            unicode_dir_name = "\u0394"
            path_with_unicode = os.path.join(tmpdir, unicode_dir_name)
            os.makedirs(path_with_unicode)

            try:
                Repo.clone_from(
                    url=self._small_repo_url(),
                    to_path=path_with_unicode,
                )
            except UnicodeEncodeError:
                self.fail("Raised UnicodeEncodeError")

    @with_rw_directory
    @skip(
        """The referenced repository was removed, and one needs to set up a new
        password controlled repo under the org's control."""
    )
    def test_leaking_password_in_clone_logs(self, rw_dir):
        password = "fakepassword1234"
        try:
            Repo.clone_from(
                url="https://fakeuser:{}@fakerepo.example.com/testrepo".format(password),
                to_path=rw_dir,
            )
        except GitCommandError as err:
            assert password not in str(err), "The error message '%s' should not contain the password" % err
        # Working example from a blank private project.
        Repo.clone_from(
            url="https://gitlab+deploy-token-392045:mLWhVus7bjLsy8xj8q2V@gitlab.com/mercierm/test_git_python",
            to_path=rw_dir,
        )

    @with_rw_repo("HEAD")
    def test_clone_unsafe_options(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upload-pack='touch {tmp_file}'",
                f"-u 'touch {tmp_file}'",
                "--config=protocol.ext.allow=always",
                "-c protocol.ext.allow=always",
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    rw_repo.clone(tmp_dir, multi_options=[unsafe_option])
                assert not tmp_file.exists()

            unsafe_options = [
                {"upload-pack": f"touch {tmp_file}"},
                {"u": f"touch {tmp_file}"},
                {"config": "protocol.ext.allow=always"},
                {"c": "protocol.ext.allow=always"},
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    rw_repo.clone(tmp_dir, **unsafe_option)
                assert not tmp_file.exists()

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason=(
            "File not created. A separate Windows command may be needed. This and the "
            "currently passing test test_clone_unsafe_options must be adjusted in the "
            "same way. Until then, test_clone_unsafe_options is unreliable on Windows."
        ),
        raises=AssertionError,
    )
    @with_rw_repo("HEAD")
    def test_clone_unsafe_options_allowed(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upload-pack='touch {tmp_file}'",
                f"-u 'touch {tmp_file}'",
            ]
            for i, unsafe_option in enumerate(unsafe_options):
                destination = tmp_dir / str(i)
                assert not tmp_file.exists()
                # The options will be allowed, but the command will fail.
                with self.assertRaises(GitCommandError):
                    rw_repo.clone(destination, multi_options=[unsafe_option], allow_unsafe_options=True)
                assert tmp_file.exists()
                tmp_file.unlink()

            unsafe_options = [
                "--config=protocol.ext.allow=always",
                "-c protocol.ext.allow=always",
            ]
            for i, unsafe_option in enumerate(unsafe_options):
                destination = tmp_dir / str(i)
                assert not destination.exists()
                rw_repo.clone(destination, multi_options=[unsafe_option], allow_unsafe_options=True)
                assert destination.exists()

    @with_rw_repo("HEAD")
    def test_clone_safe_options(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            options = [
                "--depth=1",
                "--single-branch",
                "-q",
            ]
            for option in options:
                destination = tmp_dir / option
                assert not destination.exists()
                rw_repo.clone(destination, multi_options=[option])
                assert destination.exists()

    @with_rw_repo("HEAD")
    def test_clone_from_unsafe_options(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upload-pack='touch {tmp_file}'",
                f"-u 'touch {tmp_file}'",
                "--config=protocol.ext.allow=always",
                "-c protocol.ext.allow=always",
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    Repo.clone_from(rw_repo.working_dir, tmp_dir, multi_options=[unsafe_option])
                assert not tmp_file.exists()

            unsafe_options = [
                {"upload-pack": f"touch {tmp_file}"},
                {"u": f"touch {tmp_file}"},
                {"config": "protocol.ext.allow=always"},
                {"c": "protocol.ext.allow=always"},
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    Repo.clone_from(rw_repo.working_dir, tmp_dir, **unsafe_option)
                assert not tmp_file.exists()

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason=(
            "File not created. A separate Windows command may be needed. This and the "
            "currently passing test test_clone_from_unsafe_options must be adjusted in the "
            "same way. Until then, test_clone_from_unsafe_options is unreliable on Windows."
        ),
        raises=AssertionError,
    )
    @with_rw_repo("HEAD")
    def test_clone_from_unsafe_options_allowed(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upload-pack='touch {tmp_file}'",
                f"-u 'touch {tmp_file}'",
            ]
            for i, unsafe_option in enumerate(unsafe_options):
                destination = tmp_dir / str(i)
                assert not tmp_file.exists()
                # The options will be allowed, but the command will fail.
                with self.assertRaises(GitCommandError):
                    Repo.clone_from(
                        rw_repo.working_dir, destination, multi_options=[unsafe_option], allow_unsafe_options=True
                    )
                assert tmp_file.exists()
                tmp_file.unlink()

            unsafe_options = [
                "--config=protocol.ext.allow=always",
                "-c protocol.ext.allow=always",
            ]
            for i, unsafe_option in enumerate(unsafe_options):
                destination = tmp_dir / str(i)
                assert not destination.exists()
                Repo.clone_from(
                    rw_repo.working_dir, destination, multi_options=[unsafe_option], allow_unsafe_options=True
                )
                assert destination.exists()

    @with_rw_repo("HEAD")
    def test_clone_from_safe_options(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            options = [
                "--depth=1",
                "--single-branch",
                "-q",
            ]
            for option in options:
                destination = tmp_dir / option
                assert not destination.exists()
                Repo.clone_from(rw_repo.common_dir, destination, multi_options=[option])
                assert destination.exists()

    def test_clone_from_unsafe_protocol(self):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            urls = [
                f"ext::sh -c touch% {tmp_file}",
                "fd::17/foo",
            ]
            for url in urls:
                with self.assertRaises(UnsafeProtocolError):
                    Repo.clone_from(url, tmp_dir / "repo")
                assert not tmp_file.exists()

    def test_clone_from_unsafe_protocol_allowed(self):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            urls = [
                f"ext::sh -c touch% {tmp_file}",
                "fd::/foo",
            ]
            for url in urls:
                # The URL will be allowed into the command, but the command will
                # fail since we don't have that protocol enabled in the Git config file.
                with self.assertRaises(GitCommandError):
                    Repo.clone_from(url, tmp_dir / "repo", allow_unsafe_protocols=True)
                assert not tmp_file.exists()

    def test_clone_from_unsafe_protocol_allowed_and_enabled(self):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            urls = [
                f"ext::sh -c touch% {tmp_file}",
            ]
            allow_ext = [
                "--config=protocol.ext.allow=always",
            ]
            for url in urls:
                # The URL will be allowed into the command, and the protocol is enabled,
                # but the command will fail since it can't read from the remote repo.
                assert not tmp_file.exists()
                with self.assertRaises(GitCommandError):
                    Repo.clone_from(
                        url,
                        tmp_dir / "repo",
                        multi_options=allow_ext,
                        allow_unsafe_protocols=True,
                        allow_unsafe_options=True,
                    )
                assert tmp_file.exists()
                tmp_file.unlink()

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
        with tempfile.TemporaryDirectory() as tdir, cwd(tdir):
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

    def test_daemon_export(self):
        orig_val = self.rorepo.daemon_export
        self.rorepo.daemon_export = not orig_val
        self.assertEqual(self.rorepo.daemon_export, (not orig_val))
        self.rorepo.daemon_export = orig_val
        self.assertEqual(self.rorepo.daemon_export, orig_val)

    def test_alternates(self):
        cur_alternates = self.rorepo.alternates
        # empty alternates
        self.rorepo.alternates = []
        self.assertEqual(self.rorepo.alternates, [])
        alts = ["other/location", "this/location"]
        self.rorepo.alternates = alts
        self.assertEqual(alts, self.rorepo.alternates)
        self.rorepo.alternates = cur_alternates

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

    @with_rw_repo("HEAD")
    def test_is_dirty_with_path(self, rwrepo):
        assert rwrepo.is_dirty(path="git") is False

        with open(osp.join(rwrepo.working_dir, "git", "util.py"), "at") as f:
            f.write("junk")
        assert rwrepo.is_dirty(path="git") is True
        assert rwrepo.is_dirty(path="doc") is False

        rwrepo.git.add(Git.polish_url(osp.join("git", "util.py")))
        assert rwrepo.is_dirty(index=False, path="git") is False
        assert rwrepo.is_dirty(path="git") is True

        with open(osp.join(rwrepo.working_dir, "doc", "no-such-file.txt"), "wt") as f:
            f.write("junk")
        assert rwrepo.is_dirty(path="doc") is False
        assert rwrepo.is_dirty(untracked_files=True, path="doc") is True

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

    @mock.patch.object(Git, "_call_process")
    def test_should_display_blame_information(self, git):
        git.return_value = fixture("blame")
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
            ValueError,
            "634396b2f541a9f2d58b00be1a07f0c358b999b3 missing",
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

    @mock.patch.object(Git, "_call_process")
    def test_blame_accepts_rev_opts(self, git):
        expected_args = ["blame", "HEAD", "-M", "-C", "-C", "--", "README.md"]
        boilerplate_kwargs = {"p": True, "stdout_as_string": False}
        self.rorepo.blame("HEAD", "README.md", rev_opts=["-M", "-C", "-C"])
        git.assert_called_once_with(*expected_args, **boilerplate_kwargs)

    @with_rw_repo("HEAD", bare=False)
    def test_untracked_files(self, rwrepo):
        for run, repo_add in enumerate((rwrepo.index.add, rwrepo.git.add)):
            base = rwrepo.working_tree_dir
            files = (
                join_path_native(base, "%i_test _myfile" % run),
                join_path_native(base, "%i_test_other_file" % run),
                join_path_native(base, "%i__çava verböten" % run),
                join_path_native(base, "%i_çava-----verböten" % run),
            )

            num_recently_untracked = 0
            for fpath in files:
                with open(fpath, "wb"):
                    pass
            untracked_files = rwrepo.untracked_files
            num_recently_untracked = len(untracked_files)

            # Ensure we have all names - they are relative to the git-dir.
            num_test_untracked = 0
            for utfile in untracked_files:
                num_test_untracked += join_path_native(base, utfile) in files
            self.assertEqual(len(files), num_test_untracked)

            repo_add(untracked_files)
            self.assertEqual(len(rwrepo.untracked_files), (num_recently_untracked - len(files)))
        # END for each run

    def test_config_reader(self):
        reader = self.rorepo.config_reader()  # All config files.
        assert reader.read_only
        reader = self.rorepo.config_reader("repository")  # Single config file.
        assert reader.read_only

    def test_config_writer(self):
        for config_level in self.rorepo.config_level:
            try:
                with self.rorepo.config_writer(config_level) as writer:
                    self.assertFalse(writer.read_only)
            except IOError:
                # It's okay not to get a writer for some configuration files if we
                # have no permissions.
                pass

    def test_config_level_paths(self):
        for config_level in self.rorepo.config_level:
            assert self.rorepo._get_config_path(config_level)

    def test_creation_deletion(self):
        # Just a very quick test to assure it generally works. There are specialized
        # cases in the test_refs module.
        head = self.rorepo.create_head("new_head", "HEAD~1")
        self.rorepo.delete_head(head)

        try:
            tag = self.rorepo.create_tag("new_tag", "HEAD~2")
        finally:
            self.rorepo.delete_tag(tag)
        with self.rorepo.config_writer():
            pass
        try:
            remote = self.rorepo.create_remote("new_remote", "git@server:repo.git")
        finally:
            self.rorepo.delete_remote(remote)

    def test_comparison_and_hash(self):
        # This is only a preliminary test, more testing done in test_index.
        self.assertEqual(self.rorepo, self.rorepo)
        self.assertFalse(self.rorepo != self.rorepo)
        self.assertEqual(len({self.rorepo, self.rorepo}), 1)

    @with_rw_directory
    def test_tilde_and_env_vars_in_repo_path(self, rw_dir):
        with mock.patch.dict(os.environ, {"HOME": rw_dir}):
            os.environ["HOME"] = rw_dir
            Repo.init(osp.join("~", "test.git"), bare=True)

        with mock.patch.dict(os.environ, {"FOO": rw_dir}):
            os.environ["FOO"] = rw_dir
            Repo.init(osp.join("$FOO", "test.git"), bare=True)

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

    @with_rw_repo("HEAD", bare=False)
    def test_rw_rev_parse(self, rwrepo):
        # Verify it does not confuse branches with hexsha ids.
        ahead = rwrepo.create_head("aaaaaaaa")
        assert rwrepo.rev_parse(str(ahead)) == ahead.commit

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
        self.assertRaises(ValueError, rev_parse, "0.1.4^{tree")

        # Missing starting brace.
        self.assertRaises(ValueError, rev_parse, "0.1.4^tree}")

        # REVLOG
        #######
        head = self.rorepo.head

        # Need to specify a ref when using the @ syntax.
        self.assertRaises(BadObject, rev_parse, "%s@{0}" % head.commit.hexsha)

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
        self.assertRaises(IndexError, rev_parse, "@{10000}")

        # Currently, nothing more is supported.
        self.assertRaises(NotImplementedError, rev_parse, "@{1 week ago}")

        # The last position.
        assert rev_parse("@{1}") != head.commit

    def test_repo_odbtype(self):
        target_type = GitCmdObjectDB
        self.assertIsInstance(self.rorepo.odb, target_type)

    @pytest.mark.xfail(
        sys.platform == "cygwin",
        reason="Cygwin GitPython can't find submodule SHA",
        raises=ValueError,
    )
    def test_submodules(self):
        self.assertEqual(len(self.rorepo.submodules), 1)  # non-recursive
        self.assertGreaterEqual(len(list(self.rorepo.iter_submodules())), 2)

        self.assertIsInstance(self.rorepo.submodule("gitdb"), Submodule)
        self.assertRaises(ValueError, self.rorepo.submodule, "doesn't exist")

    @with_rw_repo("HEAD", bare=False)
    def test_submodule_update(self, rwrepo):
        # Fails in bare mode.
        rwrepo._bare = True
        self.assertRaises(InvalidGitRepositoryError, rwrepo.submodule_update)
        rwrepo._bare = False

        # Test submodule creation.
        sm = rwrepo.submodules[0]
        sm = rwrepo.create_submodule(
            "my_new_sub",
            "some_path",
            join_path_native(self.rorepo.working_tree_dir, sm.path),
        )
        self.assertIsInstance(sm, Submodule)

        # NOTE: The rest of this functionality is tested in test_submodule.

    @with_rw_repo("HEAD")
    def test_git_file(self, rwrepo):
        # Move the .git directory to another location and create the .git file.
        real_path_abs = osp.abspath(join_path_native(rwrepo.working_tree_dir, ".real"))
        os.rename(rwrepo.git_dir, real_path_abs)
        git_file_path = join_path_native(rwrepo.working_tree_dir, ".git")
        with open(git_file_path, "wb") as fp:
            fp.write(fixture("git_file"))

        # Create a repo and make sure it's pointing to the relocated .git directory.
        git_file_repo = Repo(rwrepo.working_tree_dir)
        self.assertEqual(osp.abspath(git_file_repo.git_dir), real_path_abs)

        # Test using an absolute gitdir path in the .git file.
        with open(git_file_path, "wb") as fp:
            fp.write(("gitdir: %s\n" % real_path_abs).encode("ascii"))
        git_file_repo = Repo(rwrepo.working_tree_dir)
        self.assertEqual(osp.abspath(git_file_repo.git_dir), real_path_abs)

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
            for repo_type in (GitCmdObjectDB, GitDB):
                repo = Repo(self.rorepo.working_tree_dir, odbt=repo_type)
                last_commit(repo, "master", "test/test_base.py")
            # END for each repository type
        # END for each iteration

    def test_remote_method(self):
        self.assertRaises(ValueError, self.rorepo.remote, "foo-blue")
        self.assertIsInstance(self.rorepo.remote(name="origin"), Remote)

    @with_rw_directory
    def test_empty_repo(self, rw_dir):
        """Assure we can handle empty repositories"""
        r = Repo.init(rw_dir, mkdir=False, initial_branch="master")
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
        touch(new_file_path)
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
        self.assertTrue(repo.is_ancestor("master", "master"))
        self.assertTrue(repo.is_ancestor(c1, c2))
        self.assertTrue(repo.is_ancestor(c1, "master"))
        self.assertFalse(repo.is_ancestor(c2, c1))
        self.assertFalse(repo.is_ancestor("master", c1))
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

    @with_rw_directory
    def test_git_work_tree_dotgit(self, rw_dir):
        """Check that we find .git as a worktree file and find the worktree
        based on it."""
        git = Git(rw_dir)
        if git.version_info[:3] < (2, 5, 1):
            raise RuntimeError("worktree feature unsupported (test needs git 2.5.1 or later)")

        rw_master = self.rorepo.clone(join_path_native(rw_dir, "master_repo"))
        branch = rw_master.create_head("aaaaaaaa")
        worktree_path = join_path_native(rw_dir, "worktree_repo")
        if Git.is_cygwin():
            worktree_path = cygpath(worktree_path)
        rw_master.git.worktree("add", worktree_path, branch.name)

        # This ensures that we can read the repo's gitdir correctly.
        repo = Repo(worktree_path)
        self.assertIsInstance(repo, Repo)

        # This ensures we're able to actually read the refs in the tree, which means we
        # can read commondir correctly.
        commit = repo.head.commit
        self.assertIsInstance(commit, Object)

        # This ensures we can read the remotes, which confirms we're reading the config
        # correctly.
        origin = repo.remotes.origin
        self.assertIsInstance(origin, Remote)

        self.assertIsInstance(repo.heads["aaaaaaaa"], Head)

    @with_rw_directory
    def test_git_work_tree_env(self, rw_dir):
        """Check that we yield to GIT_WORK_TREE."""
        # Clone a repo.
        # Move .git directory to a subdirectory.
        # Set GIT_DIR and GIT_WORK_TREE appropriately.
        # Check that: repo.working_tree_dir == rw_dir

        self.rorepo.clone(join_path_native(rw_dir, "master_repo"))

        repo_dir = join_path_native(rw_dir, "master_repo")
        old_git_dir = join_path_native(repo_dir, ".git")
        new_subdir = join_path_native(repo_dir, "gitdir")
        new_git_dir = join_path_native(new_subdir, "git")
        os.mkdir(new_subdir)
        os.rename(old_git_dir, new_git_dir)

        to_patch = {"GIT_DIR": new_git_dir, "GIT_WORK_TREE": repo_dir}

        with mock.patch.dict(os.environ, to_patch):
            r = Repo()
            self.assertEqual(r.working_tree_dir, repo_dir)
            self.assertEqual(r.working_dir, repo_dir)

    @with_rw_directory
    def test_rebasing(self, rw_dir):
        r = Repo.init(rw_dir, initial_branch="master")
        fp = osp.join(rw_dir, "hello.txt")
        r.git.commit(
            "--allow-empty",
            message="init",
        )
        with open(fp, "w") as fs:
            fs.write("hello world")
        r.git.add(Git.polish_url(fp))
        r.git.commit(message="English")
        self.assertEqual(r.currently_rebasing_on(), None)
        r.git.checkout("HEAD^1")
        with open(fp, "w") as fs:
            fs.write("Hola Mundo")
        r.git.add(Git.polish_url(fp))
        r.git.commit(message="Spanish")
        commitSpanish = r.commit()
        try:
            r.git.rebase("master")
        except GitCommandError:
            pass
        self.assertEqual(r.currently_rebasing_on(), commitSpanish)

    @with_rw_directory
    def test_do_not_strip_newline_in_stdout(self, rw_dir):
        r = self.create_repo_commit_hello_newline(rw_dir)
        self.assertEqual(r.git.show("HEAD:hello.txt", strip_newline_in_stdout=False), "hello\n")

    def create_repo_commit_hello_newline(self, rw_dir):
        r = Repo.init(rw_dir)
        fp = osp.join(rw_dir, "hello.txt")
        with open(fp, "w") as fs:
            fs.write("hello\n")
        r.git.add(Git.polish_url(fp))
        r.git.commit(message="init")
        return r

    @with_rw_directory
    def test_warn_when_strip_newline_in_stdout(self, rw_dir):
        r = self.create_repo_commit_hello_newline(rw_dir)
        with pytest.warns(DeprecationWarning):
            self.assertEqual(r.git.show("HEAD:hello.txt", strip_newline_in_stdout=True), "hello")

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason=R"fatal: could not create leading directories of '--upload-pack=touch C:\Users\ek\AppData\Local\Temp\tmpnantqizc\pwn': Invalid argument",  # noqa: E501
        raises=GitCommandError,
    )
    @with_rw_repo("HEAD")
    def test_clone_command_injection(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            unexpected_file = tmp_dir / "pwn"
            assert not unexpected_file.exists()

            payload = f"--upload-pack=touch {unexpected_file}"
            rw_repo.clone(payload)

            assert not unexpected_file.exists()
            # A repo was cloned with the payload as name.
            assert pathlib.Path(payload).exists()

    @with_rw_repo("HEAD")
    def test_clone_from_command_injection(self, rw_repo):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            temp_repo = Repo.init(tmp_dir / "repo")
            unexpected_file = tmp_dir / "pwn"

            assert not unexpected_file.exists()
            payload = f"--upload-pack=touch {unexpected_file}"
            with self.assertRaises(GitCommandError):
                rw_repo.clone_from(payload, temp_repo.common_dir)

            assert not unexpected_file.exists()

    def test_ignored_items_reported(self):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            temp_repo = Repo.init(tmp_dir / "repo")

            gi = tmp_dir / "repo" / ".gitignore"

            with open(gi, "w") as file:
                file.write("ignored_file.txt\n")
                file.write("ignored_dir/\n")

            assert temp_repo.ignored(["included_file.txt", "included_dir/file.txt"]) == []
            assert temp_repo.ignored(["ignored_file.txt"]) == ["ignored_file.txt"]
            assert temp_repo.ignored(["included_file.txt", "ignored_file.txt"]) == ["ignored_file.txt"]
            assert temp_repo.ignored(
                ["included_file.txt", "ignored_file.txt", "included_dir/file.txt", "ignored_dir/file.txt"]
            ) == ["ignored_file.txt", "ignored_dir/file.txt"]

    def test_ignored_raises_error_w_symlink(self):
        with tempfile.TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            temp_repo = Repo.init(tmp_dir / "repo")

            os.mkdir(tmp_dir / "target")
            os.symlink(tmp_dir / "target", tmp_dir / "symlink")

            with pytest.raises(GitCommandError):
                temp_repo.ignored(tmp_dir / "symlink/file.txt")
