# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import os
import os.path as osp
import pathlib
import sys
from unittest import skip
from unittest import mock

from git import Git, GitCommandError, Repo
from git.exc import UnsafeOptionError, UnsafeProtocolError

from test.cleanup import TemporaryDirectory
from test.lib import TestBase, with_rw_directory, with_rw_repo, PathLikeMock

from pathlib import Path
import re

import git
import pytest


@pytest.mark.parametrize("clone_method", ["clone", "clone_from"])
@pytest.mark.parametrize("path_type", [str, Path, PathLikeMock])
@pytest.mark.parametrize("name", ["$GITPYTHON_TEST_SECRET", "${GITPYTHON_TEST_SECRET}", "%GITPYTHON_TEST_SECRET%"])
def test_clone_preserves_literal_separate_git_dir(tmp_path, monkeypatch, caplog, clone_method, path_type, name):
    monkeypatch.setenv("GITPYTHON_TEST_SECRET", "sensitive-value")
    caplog.set_level("DEBUG", logger="git.cmd")
    separate_git_dir = tmp_path / name
    options = {"separate_git_dir": path_type(str(separate_git_dir)), "allow_unsafe_options": True}

    with Repo.init(tmp_path / "source") as source:
        if clone_method == "clone":
            cloned = source.clone(tmp_path / "clone", **options)
        else:
            cloned = Repo.clone_from(source.git_dir, tmp_path / "clone", **options)
        with cloned:
            assert (separate_git_dir / "HEAD").is_file()
            assert separate_git_dir.samefile(cloned.git_dir)

    assert not (tmp_path / "sensitive-value").exists()
    assert "sensitive-value" not in caplog.text


@pytest.mark.parametrize("clone_method", ["clone", "clone_from"])
def test_clone_clears_ambient_source_storage_environment(tmp_path, clone_method):
    source = Repo.init(tmp_path / "source")
    initial = source.index.commit("initial")
    environment = {
        "GIT_DIR": str(source.git_dir),
        "GIT_COMMON_DIR": str(source.common_dir),
        "GIT_WORK_TREE": str(source.working_tree_dir),
        "GIT_OBJECT_DIRECTORY": str(source.odb.root_path()),
    }
    destination = tmp_path / "clone"
    with mock.patch.dict(os.environ, environment):
        cloned = source.clone(destination) if clone_method == "clone" else Repo.clone_from(source.git_dir, destination)
        assert os.path.samefile(cloned.working_tree_dir, destination)
        assert os.path.samefile(cloned.common_dir, destination / ".git")
        assert os.path.samefile(cloned.git.rev_parse("--show-toplevel"), destination)
        assert cloned.head.commit == initial
        created = cloned.index.commit("clone-only commit")
        assert source.head.commit == initial
        assert not source.odb.has_object(created.binsha)
    assert cloned.head.commit == created


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
        with TemporaryDirectory() as tmpdir:
            unicode_dir_name = "\u0394"
            path_with_unicode = os.path.join(tmpdir, unicode_dir_name)
            os.makedirs(path_with_unicode)

            try:
                Repo.clone_from(
                    url=self._small_repo_url(),
                    to_path=path_with_unicode,
                    # Local clones hardlink the reconstructed smmap repository's
                    # read-only metadata, which Windows cannot remove at cleanup.
                    no_hardlinks=True,
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
        with TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upload-pack='touch {tmp_file}'",
                f"--upl='touch {tmp_file}'",
                f"-u 'touch {tmp_file}'",
                f"-utouch {tmp_file}; false",
                f"-futouch${{IFS}}{tmp_file}; false",
                f"-qutouch${{IFS}}{tmp_file}; false",
                "--config=protocol.ext.allow=always",
                "--conf=protocol.ext.allow=always",
                "-c protocol.ext.allow=always",
                "-cprotocol.ext.allow=always",
                "-vcprotocol.ext.allow=always",
                f"--template={tmp_dir}",
                f"--bundle-uri=file://{tmp_dir}",
                f"--separate-git-dir={tmp_dir / 'git-dir'}",
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    rw_repo.clone(tmp_dir, multi_options=[unsafe_option])
                assert not tmp_file.exists()

            unsafe_options = [
                {"upload-pack": f"touch {tmp_file}"},
                {"upload_pack": f"touch {tmp_file}"},
                {"upl": f"touch {tmp_file}"},
                {"u": f"touch {tmp_file}"},
                {"config": "protocol.ext.allow=always"},
                {"conf": "protocol.ext.allow=always"},
                {"c": "protocol.ext.allow=always"},
                {"template": tmp_dir},
                {"bundle_uri": f"file://{tmp_dir}"},
                {"separate_git_dir": tmp_dir / "git-dir"},
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    rw_repo.clone(tmp_dir, **unsafe_option)
                assert not tmp_file.exists()

    @with_rw_repo("HEAD")
    def test_clone_unsafe_options_abbreviated(self, rw_repo):
        with TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upl='touch {tmp_file}'",
                f"--upload-pac='touch {tmp_file}'",
                "--conf=protocol.ext.allow=always",
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    rw_repo.clone(tmp_dir, multi_options=[unsafe_option])
                assert not tmp_file.exists()

            unsafe_kwargs = [
                {"upl": f"touch {tmp_file}"},
                {"upload_pac": f"touch {tmp_file}"},
                {"conf": "protocol.ext.allow=always"},
            ]
            for unsafe_option in unsafe_kwargs:
                with self.assertRaises(UnsafeOptionError):
                    rw_repo.clone(tmp_dir, **unsafe_option)
                assert not tmp_file.exists()

    @with_rw_repo("HEAD")
    def test_clone_unsafe_options_are_checked_after_splitting_multi_options(self, rw_repo):
        with TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            payload = "--single-branch --config protocol.ext.allow=always"

            with self.assertRaises(UnsafeOptionError):
                rw_repo.clone(tmp_dir, multi_options=[payload])

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
        with TemporaryDirectory() as tdir:
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
        with TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            options = [
                "--depth=1",
                "--single-branch",
                "--origin upload",
                "-q",
                "-oupstream",
            ]
            for option in options:
                destination = tmp_dir / option
                assert not destination.exists()
                rw_repo.clone(destination, multi_options=[option])
                assert destination.exists()

    @with_rw_repo("HEAD")
    def test_clone_from_unsafe_options(self, rw_repo):
        with TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            tmp_file = tmp_dir / "pwn"
            unsafe_options = [
                f"--upload-pack='touch {tmp_file}'",
                f"-u 'touch {tmp_file}'",
                f"-utouch {tmp_file}; false",
                f"-futouch${{IFS}}{tmp_file}; false",
                f"-qutouch${{IFS}}{tmp_file}; false",
                "--config=protocol.ext.allow=always",
                "-c protocol.ext.allow=always",
                "-cprotocol.ext.allow=always",
                "-vcprotocol.ext.allow=always",
                f"--separate-git-dir={tmp_dir / 'git-dir'}",
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    Repo.clone_from(rw_repo.working_dir, tmp_dir, multi_options=[unsafe_option])
                assert not tmp_file.exists()

            unsafe_options = [
                {"upload-pack": f"touch {tmp_file}"},
                {"upload_pack": f"touch {tmp_file}"},
                {"u": f"touch {tmp_file}"},
                {"config": "protocol.ext.allow=always"},
                {"c": "protocol.ext.allow=always"},
                {"separate_git_dir": tmp_dir / "git-dir"},
            ]
            for unsafe_option in unsafe_options:
                with self.assertRaises(UnsafeOptionError):
                    Repo.clone_from(rw_repo.working_dir, tmp_dir, **unsafe_option)
                assert not tmp_file.exists()

    @with_rw_repo("HEAD")
    def test_clone_from_unsafe_options_are_checked_after_splitting_multi_options(self, rw_repo):
        with TemporaryDirectory() as tdir:
            tmp_dir = pathlib.Path(tdir)
            payload = "--single-branch --config protocol.ext.allow=always"

            with self.assertRaises(UnsafeOptionError):
                Repo.clone_from(rw_repo.working_dir, tmp_dir, multi_options=[payload])

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
        with TemporaryDirectory() as tdir:
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
        with TemporaryDirectory() as tdir:
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
        with TemporaryDirectory() as tdir:
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

    def test_clone_from_does_not_expand_environment_variables_in_url(self):
        urls = [
            "https://example.com/$GITPYTHON_TEST_SECRET/repo.git",
            "https://example.com/${GITPYTHON_TEST_SECRET}/repo.git",
            "https://example.com/%GITPYTHON_TEST_SECRET%/repo.git",
        ]
        with mock.patch.dict(os.environ, {"GITPYTHON_TEST_SECRET": "sensitive-value"}):
            for url in urls:
                with mock.patch.object(Git, "_call_process_safe", side_effect=RuntimeError) as call_process:
                    with self.assertRaises(RuntimeError):
                        Repo.clone_from(url, "unused")

                assert call_process.call_args[0][3] == url

    @with_rw_directory
    def test_clone_from_does_not_expand_environment_variables_in_stored_url(self, rw_dir):
        url = pathlib.Path(rw_dir) / "$GITPYTHON_TEST_SECRET" / "source"
        Git().init(url)

        with mock.patch.dict(os.environ, {"GITPYTHON_TEST_SECRET": "sensitive-value"}):
            cloned = Repo.clone_from(url, pathlib.Path(rw_dir) / "clone")

        assert cloned.remotes.origin.url == Git.polish_url(str(url))

    def test_clone_from_checks_polished_url_for_unsafe_protocol(self):
        with mock.patch.object(Git, "polish_url", return_value="ext::command"):
            with mock.patch.object(Git, "_call_process") as call_process:
                with self.assertRaises(UnsafeProtocolError):
                    Repo.clone_from("$GITPYTHON_TEST_URL", "unused")

        call_process.assert_not_called()

    def test_polish_url_does_not_expand_environment_variables_for_cygwin(self):
        urls = ["$GITPYTHON_TEST_SECRET/repo", "user@example.com:$GITPYTHON_TEST_SECRET/repo"]
        with mock.patch.dict(os.environ, {"GITPYTHON_TEST_SECRET": "sensitive-value"}):
            for url in urls:
                assert Git.polish_url(url, is_cygwin=True) == url

    def test_clone_from_unsafe_protocol_allowed(self):
        with TemporaryDirectory() as tdir:
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
        with TemporaryDirectory() as tdir:
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
