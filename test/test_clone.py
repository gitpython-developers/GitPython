# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import os
import os.path as osp
import pathlib
import sys
import tempfile
from unittest import skip

from git import GitCommandError, Repo
from git.exc import UnsafeOptionError, UnsafeProtocolError

from test.lib import TestBase, with_rw_directory, with_rw_repo, PathLikeMock

from pathlib import Path
import re

import git
import pytest


class TestClone(TestBase):
    @with_rw_directory
    def test_checkout_in_non_empty_dir(self, rw_dir):
        non_empty_dir = Path(rw_dir)
        garbage_file = non_empty_dir / "not-empty"
        garbage_file.write_text("Garbage!")

        # Verify that cloning into the non-empty dir fails while complaining about the
        # target directory not being empty/non-existent.
        try:
            self.rorepo.clone(non_empty_dir)
        except git.GitCommandError as exc:
            self.assertTrue(exc.stderr, "GitCommandError's 'stderr' is unexpectedly empty")
            expr = re.compile(r"(?is).*\bfatal:\s+destination\s+path\b.*\bexists\b.*\bnot\b.*\bempty\s+directory\b")
            self.assertTrue(
                expr.search(exc.stderr),
                '"%s" does not match "%s"' % (expr.pattern, exc.stderr),
            )
        else:
            self.fail("GitCommandError not raised")

    @with_rw_directory
    def test_clone_from_pathlib(self, rw_dir):
        original_repo = Repo.init(osp.join(rw_dir, "repo"))

        Repo.clone_from(pathlib.Path(original_repo.git_dir), pathlib.Path(rw_dir) / "clone_pathlib")

    @with_rw_directory
    def test_clone_from_pathlike(self, rw_dir):
        original_repo = Repo.init(osp.join(rw_dir, "repo"))
        Repo.clone_from(PathLikeMock(original_repo.git_dir), PathLikeMock(os.path.join(rw_dir, "clone_pathlike")))

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
