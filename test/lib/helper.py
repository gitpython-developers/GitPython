# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

__all__ = [
    "fixture_path",
    "fixture",
    "StringProcessAdapter",
    "with_rw_directory",
    "with_rw_repo",
    "with_rw_and_rw_remote_repo",
    "patch_git_config",
    "PathLikeMock",
    "TestBase",
    "TestCase",
    "SkipTest",
    "skipIf",
    "GIT_REPO",
    "GIT_DAEMON_PORT",
    "xfail_if_raises",
    "symlinks_supported",
    "requires_symlinks",
]

import contextlib
from dataclasses import dataclass
from functools import wraps
import gc
import io
import logging
import os
import os.path as osp
from pathlib import Path
from stat import S_ISLNK, ST_MODE
import socket
import textwrap
import time
import unittest
from unittest import mock
from typing import Union, Type, Tuple

import pytest
from gix import testtools

from git.util import cwd
from test.cleanup import TemporaryDirectory
from test.lib.fixtures import read_only_fixture, writable_fixture

TestCase = unittest.TestCase
SkipTest = unittest.SkipTest
skipIf = unittest.skipIf

ospd = osp.dirname

GIT_REPO = os.environ.get("GIT_PYTHON_TEST_GIT_REPO_BASE", ospd(ospd(ospd(__file__))))
GIT_DAEMON_PORT = os.environ.get("GIT_PYTHON_TEST_GIT_DAEMON_PORT", "19418")

_logger = logging.getLogger(__name__)


@dataclass
class PathLikeMock:
    path: str

    def __fspath__(self) -> str:
        return self.path


# { Routines


def fixture_path(name):
    return osp.join(ospd(ospd(__file__)), "fixtures", name)


def fixture(name):
    with open(fixture_path(name), "rb") as fd:
        return fd.read()


# } END routines

# { Adapters


@contextlib.contextmanager
def patch_git_config(name, value):
    """Temporarily add a git config name-value pair, using environment variables."""
    pair_index = int(os.getenv("GIT_CONFIG_COUNT", "0"))

    # This is recomputed each time the context is entered, for compatibility with
    # existing GIT_CONFIG_* environment variables, even if changed in this process.
    patcher = mock.patch.dict(
        os.environ,
        {
            "GIT_CONFIG_COUNT": str(pair_index + 1),
            f"GIT_CONFIG_KEY_{pair_index}": name,
            f"GIT_CONFIG_VALUE_{pair_index}": value,
        },
    )

    with patcher:
        yield


class StringProcessAdapter:
    """Allows strings to be used as process objects returned by subprocess.Popen.

    This is tailored to work with the test system only.
    """

    def __init__(self, input_string):
        self.stdout = io.BytesIO(input_string)
        self.stderr = io.BytesIO()

    def wait(self, stderr=None):
        return 0

    poll = wait


# } END adapters

# { Decorators


def with_rw_directory(func=None, *, script="empty.sh", args=(), execute=False):
    """Create a temporary directory which can be written to, remove it if the
    test succeeds, but leave it otherwise to aid additional debugging.

    Cleanup is best-effort: a locked file must not change the test result.
    """

    if func is None:
        return lambda wrapped: with_rw_directory(wrapped, script=script, args=args, execute=execute)

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        temporary = writable_fixture(script, *fixture_args, execute=execute)
        path = str(temporary.path())
        keep = False
        try:
            return func(self, path, *args, **kwargs)
        except Exception:
            _logger.info(
                "%s %s.%s failed, output is at %r\n",
                "Test" if func.__name__.startswith("test_") else "Helper",
                type(self).__name__,
                func.__name__,
                path,
            )
            keep = True
            raise
        finally:
            # Need to collect here to be sure all handles have been closed. It appears
            # a Windows-only issue. In fact things should be deleted, as well as
            # memory maps closed, once objects go out of scope. For some reason
            # though this is not the case here unless we collect explicitly.
            gc.collect()
            temporary.close(keep=keep)

    fixture_args = args
    return wrapper


def with_rw_repo(working_tree_ref, bare=False):
    """Same as with_bare_repo, but clones the rorepo as non-bare repository, checking
    out the working tree at the given working_tree_ref with an attached HEAD,
    regardless of the source repository's HEAD state.

    This repository type is more costly due to the working copy checkout.

    To make working with relative paths easier, the cwd will be set to the working
    dir of the repository.
    """
    assert isinstance(working_tree_ref, str), "Decorator requires ref name for working tree checkout"

    def argument_passer(func):
        @wraps(func)
        def repo_creator(self, *args, **kwargs):
            from git import Repo

            temporary = writable_fixture(
                "history.sh",
                self.rorepo.working_dir,
                self.rorepo.head.commit.hexsha,
                working_tree_ref,
                "bare" if bare else "worktree",
            )
            repo_dir = temporary.path() / "repo"
            rw_repo = Repo(repo_dir)
            keep = False

            prev_cwd = os.getcwd()
            os.chdir(rw_repo.working_dir)
            try:
                return func(self, rw_repo, *args, **kwargs)
            except:  # noqa: E722
                _logger.info("Keeping repo after failure: %s", repo_dir)
                keep = True
                raise
            finally:
                os.chdir(prev_cwd)
                rw_repo.close()
                rw_repo = None
                temporary.close(keep=keep)
                # END rm test repo if possible
            # END cleanup

        # END rw repo creator
        return repo_creator

    # END argument passer
    return argument_passer


@contextlib.contextmanager
def git_daemon_launched(base_path, ip, port):
    from git import Git  # Avoid circular deps.

    gd = None
    try:
        # Killing a `git daemon` wrapper can leave its child listening on any OS.
        daemon_cmd = [
            osp.join(Git()._call_process("--exec-path"), "git-daemon"),
            "--enable=receive-pack",
            "--reuseaddr",
            "--listen=%s" % ip,
            "--port=%s" % port,
            "--base-path=%s" % base_path,
            base_path,
        ]
        gd = Git().execute(daemon_cmd, as_process=True)

        # Wait until git daemon listens for connections.
        for _attempt in range(1, 30):
            try:
                socket.create_connection((ip, port), timeout=30).close()
                break
            except ConnectionRefusedError:
                time.sleep(0.5)

    except Exception as ex:
        msg = textwrap.dedent(
            """
        Launching git-daemon failed due to: %s
          Probably test will fail subsequently.

          BUT you may start *git-daemon* manually with this command:"
                git daemon --enable=receive-pack --reuseaddr --listen=%s --port=%s --base-path=%s %s
          You may also run the daemon on a different port by passing --port=<port>"
          and setting the environment variable GIT_PYTHON_TEST_GIT_DAEMON_PORT to <port>
        """
        )
        _logger.warning(msg, ex, ip, port, base_path, base_path, exc_info=1)

        yield  # OK, assume daemon started manually.

    else:
        yield  # Yield outside try, to avoid catching
    finally:
        if gd:
            try:
                _logger.debug("Killing git-daemon...")
                gd.proc.kill()
                gd.proc.wait(timeout=5)
            except Exception as ex:
                # Either it has died (and we're here), or it won't die, again here...
                _logger.debug("Hidden error while Killing git-daemon: %s", ex, exc_info=1)


def with_rw_and_rw_remote_repo(working_tree_ref):
    """Same as with_rw_repo, but also provides a writable remote repository from which
    the rw_repo has been forked as well as a handle for a git-daemon that may be started
    to run the remote_repo.

    The remote repository was cloned as bare repository from the ro repo, whereas the rw
    repo has a working tree and was cloned from the remote repository.

    remote_repo has two remotes: origin and daemon_origin. One uses a local url, the
    other uses a server url. The daemon setup must be done on system level and should be
    an inetd service that serves tempdir.gettempdir() and all directories in it.

    The following sketch demonstrates this::

        rorepo ---<bare clone>---> rw_remote_repo ---<clone>---> rw_repo

    The test case needs to support the following signature::

        def case(self, rw_repo, rw_daemon_repo)

    This setup allows you to test push and pull scenarios and hooks nicely.

    See working dir info in :func:`with_rw_repo`.

    :note: We attempt to launch our own invocation of git-daemon, which will be shut
        down at the end of the test.
    """
    from git import Git, Repo  # To avoid circular deps.

    assert isinstance(working_tree_ref, str), "Decorator requires ref name for working tree checkout"

    def argument_passer(func):
        @wraps(func)
        def remote_repo_creator(self, *args, **kwargs):
            temporary = writable_fixture(
                "history.sh",
                self.rorepo.working_dir,
                self.rorepo.head.commit.hexsha,
                working_tree_ref,
                "remote",
                GIT_DAEMON_PORT,
            )
            rw_daemon_repo_dir = temporary.path() / "remote"
            rw_repo_dir = temporary.path() / "repo"
            rw_daemon_repo = Repo(rw_daemon_repo_dir)
            rw_repo = Repo(rw_repo_dir)
            keep = False
            try:
                with git_daemon_launched(
                    Git.polish_url(str(temporary.path())),
                    "127.0.0.1",
                    GIT_DAEMON_PORT,
                ):
                    # Try listing remotes, to diagnose whether the daemon is up.
                    rw_repo.git.ls_remote(rw_repo.remotes.daemon_origin)

                    with cwd(rw_repo.working_dir):
                        try:
                            return func(self, rw_repo, rw_daemon_repo, *args, **kwargs)
                        except:  # noqa: E722
                            _logger.info(
                                "Keeping repos after failure: \n  rw_repo_dir: %s \n  rw_daemon_repo_dir: %s",
                                rw_repo_dir,
                                rw_daemon_repo_dir,
                            )
                            keep = True
                            raise

            finally:
                rw_repo.close()
                rw_daemon_repo.close()
                del rw_repo
                del rw_daemon_repo
                temporary.close(keep=keep)
            # END cleanup

        # END bare repo creator
        return remote_repo_creator
        # END remote repo creator

    # END argument parser

    return argument_passer


# } END decorators


class TestBase(TestCase):
    """Base class providing default functionality to all tests such as:

    - Utility functions provided by the TestCase base of the unittest method such as::

        self.fail("todo")
        self.assertRaises(...)

    - Class level repository which is considered read-only as it is shared among
      all test cases in your type.

      Access it using::

        self.rorepo  # 'ro' stands for read-only

      The rorepo is a scripted clone of your project's git repo. If you refer to specific
      shas for your objects, be sure you choose some that are part of the immutable
      portion of the project history (so that tests don't fail for others).
    """

    def _small_repo_url(self):
        """:return: A path to a small, clonable repository"""
        from git.cmd import Git

        return Git.polish_url(self._dependency_repo_factory("smmap"))

    def _gitdb_repo_url(self):
        """:return: A local gitdb repository reconstructed from merged history"""
        from git.cmd import Git

        return Git.polish_url(self._dependency_repo_factory("gitdb"))

    @classmethod
    def setUpClass(cls):
        """Dynamically add a read-only repository to our actual type.

        This way, each test type has its own repository.
        """
        from git import Repo

        gc.collect()
        source = Path(GIT_REPO).resolve()
        revision = testtools.git(source, "rev-parse HEAD").strip()
        cls.rorepo = Repo(read_only_fixture("history.sh", source, revision, revision, "baseline") / "repo")

    @classmethod
    def tearDownClass(cls):
        cls.rorepo.close()
        cls.rorepo.git = None

    def _make_file(self, rela_path, data, repo=None):
        """
        Create a file at the given path relative to our repository, filled with the
        given data.

        :return: An absolute path to the created file.
        """
        repo = repo or self.rorepo
        abs_path = osp.join(repo.working_tree_dir, rela_path)
        with open(abs_path, "w") as fp:
            fp.write(data)
        return abs_path


def symlinks_supported() -> bool:
    """Check whether this process can actually create a symlink.

    On Windows the platform alone doesn't decide it: creating a symlink needs either
    Developer Mode or SeCreateSymbolicLinkPrivilege, and an unprivileged process gets
    OSError (WinError 1314) instead.
    """
    with TemporaryDirectory(prefix="gitpython-symlink-check-") as temp_dir:
        link_path = osp.join(temp_dir, "link")
        try:
            os.symlink("missing-target", link_path)
        except (NotImplementedError, OSError):
            return False
        return S_ISLNK(os.lstat(link_path)[ST_MODE])


requires_symlinks = pytest.mark.skipif(
    not symlinks_supported(),
    reason="symlinks are unavailable, or need privileges this process doesn't have",
)


@contextlib.contextmanager
def xfail_if_raises(
    condition: bool,
    *,
    raises: Union[Type[BaseException], Tuple[Type[BaseException], ...]],
    reason: str = "",
    strict: bool = False,
):
    """Approximates the behavior of @pytest.mark.xfail(..., raises=...) as a context
    manager that can be used within a test, such as when the condition is complex or has
    side effects

    One difference is it will not report XPASS if the test passes, but setting `strict`
    simulates it by raising an exception"""
    try:
        yield
    except raises:
        if condition:
            pytest.xfail(reason)
        raise
    if strict and condition:
        pytest.fail("[XPASS(strict)] " + reason)
