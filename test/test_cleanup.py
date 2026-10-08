# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Cleanup failures must not fail, skip, or hide the result of a test."""

from contextlib import suppress
import errno
import gc
import os
from pathlib import Path
import socket
import stat
import sys
from types import SimpleNamespace
import weakref

import pytest

from git import Actor, Repo
from git.util import rmtree
from test import cleanup
from test.cleanup import TemporaryDirectory, cleanup_directory
from test.lib import requires_symlinks, with_rw_and_rw_remote_repo, with_rw_directory, with_rw_repo
from test.lib.helper import git_daemon_launched


@pytest.fixture
def locked_file(monkeypatch):
    """Simulate a persistent sharing violation without affecting other files."""
    unlink = os.unlink

    def unlink_unless_locked(path, *args, **kwargs):
        if Path(path).name == "locked":
            raise PermissionError(errno.EACCES, "file is in use", os.fspath(path))
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink_unless_locked)


@pytest.mark.parametrize(
    "version_info",
    [
        (3, 8),
        pytest.param(
            (3, 12),
            marks=pytest.mark.skipif(
                sys.version_info < (3, 12), reason="shutil.rmtree(onexc=...) requires Python 3.12"
            ),
        ),
    ],
)
def test_cleanup_continues_after_locked_file(tmp_path, locked_file, caplog, monkeypatch, version_info):
    monkeypatch.setattr(cleanup, "sys", SimpleNamespace(platform=sys.platform, version_info=version_info))
    directory = tmp_path / "owned"
    nested = directory / "nested"
    nested.mkdir(parents=True)
    (nested / "locked").touch()
    (nested / "removable").touch()
    (directory / "removable").touch()

    assert not cleanup_directory(directory)

    assert (nested / "locked").exists()
    assert not (nested / "removable").exists()
    assert not (directory / "removable").exists()
    assert len(caplog.records) == 1
    assert repr(str(directory)) in caplog.text
    assert "file is in use" in caplog.text


def test_cleanup_removes_readonly_files_and_tolerates_missing_directory(tmp_path):
    directory = TemporaryDirectory(dir=tmp_path)
    file = Path(directory.name, "readonly")
    file.touch()
    file.chmod(stat.S_IRUSR)
    if sys.platform == "win32":
        Path(directory.name).chmod(stat.S_IRUSR | stat.S_IXUSR)

    directory.cleanup()
    directory.cleanup()

    assert not Path(directory.name).exists()
    assert cleanup_directory(directory.name)


@requires_symlinks
@pytest.mark.parametrize("locked_link", [False, True])
def test_cleanup_does_not_touch_symlink_target(tmp_path, monkeypatch, locked_link):
    target = tmp_path / "outside"
    target.mkdir()
    file = target / "readonly"
    file.write_text("keep", encoding="utf-8")
    file.chmod(stat.S_IRUSR)
    mode = file.stat().st_mode
    unlink = os.unlink

    def unlink_unless_locked(path, *args, **kwargs):
        if locked_link and Path(path).name == "link":
            raise PermissionError("link is in use")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink_unless_locked)

    with TemporaryDirectory(dir=tmp_path) as directory:
        Path(directory, "link").symlink_to(target, target_is_directory=True)

    assert Path(directory).exists() is locked_link
    assert file.read_text(encoding="utf-8") == "keep"
    assert file.stat().st_mode == mode


def test_cleanup_ignores_filesystem_errors_outside_rmtree_callback(tmp_path, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise OSError(errno.EIO, "filesystem unavailable")

    monkeypatch.setattr(cleanup.shutil, "rmtree", fail)
    assert not cleanup_directory(tmp_path / "owned")
    assert "filesystem unavailable" in caplog.text


@pytest.mark.parametrize("error_type", [AssertionError, PermissionError])
def test_temporary_directory_preserves_test_body_error(tmp_path, locked_file, error_type):
    error = error_type("failure in the operation under test")

    with pytest.raises(error_type) as caught:
        with TemporaryDirectory(dir=tmp_path) as directory:
            Path(directory, "locked").touch()
            raise error

    assert caught.value is error
    assert Path(directory, "locked").exists()


def test_implicit_cleanup_is_also_best_effort(tmp_path, locked_file, caplog):
    directory = TemporaryDirectory(dir=tmp_path)
    path = Path(directory.name)
    (path / "locked").touch()
    (path / "removable").touch()
    reference = weakref.ref(directory)

    del directory
    gc.collect()

    assert reference() is None
    assert (path / "locked").exists()
    assert not (path / "removable").exists()
    assert repr(str(path)) in caplog.text


def test_public_rmtree_remains_strict(tmp_path, locked_file, monkeypatch):
    monkeypatch.setattr(sys.modules["git.util"], "HIDE_WINDOWS_KNOWN_ERRORS", False)
    directory = tmp_path / "strict"
    directory.mkdir()
    (directory / "locked").touch()

    with pytest.raises(PermissionError, match="file is in use"):
        rmtree(directory)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows denies removal of a file opened without delete sharing")
def test_real_windows_file_lock_and_explicit_retry(tmp_path, caplog):
    directory = TemporaryDirectory(dir=tmp_path)
    locked = Path(directory.name, "locked")
    locked.touch()
    removable = Path(directory.name, "removable")
    removable.touch()

    with locked.open("rb"):
        with pytest.raises(PermissionError):
            locked.unlink()
        directory.cleanup()
        assert locked.exists()
        assert not removable.exists()

    assert repr(directory.name) in caplog.text
    directory.cleanup()
    assert not Path(directory.name).exists()


@pytest.fixture
def source_repo(tmp_path):
    with Repo.init(tmp_path / "source", initial_branch="master") as repo:
        actor = Actor("Test", "test@example.invalid")
        repo.index.commit("fixture", author=actor, committer=actor, skip_hooks=True)
        yield repo


def test_git_daemon_releases_port_and_can_restart(tmp_path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        address = listener.getsockname()

    for _ in range(2):
        with git_daemon_launched(str(tmp_path), *address):
            with socket.create_connection(address, timeout=2) as connection:
                # Make the server close first so an orderly shutdown leaves TIME_WAIT.
                connection.sendall(b"0000")
                with suppress(ConnectionResetError):  # Git for Windows resets rejected requests.
                    assert connection.recv(1) == b""

        with pytest.raises(ConnectionRefusedError):
            with socket.create_connection(address, timeout=2):
                pass


@pytest.mark.parametrize("decorator", [with_rw_directory, with_rw_repo("HEAD"), with_rw_and_rw_remote_repo("HEAD")])
def test_decorators_preserve_success_with_locked_cleanup(source_repo, tmp_path, monkeypatch, locked_file, decorator):
    monkeypatch.setattr(cleanup.tempfile, "tempdir", str(tmp_path))
    directories = []
    repositories = []
    previous_cwd = os.getcwd()

    @decorator
    def case(self, *resources):
        for resource in resources:
            if isinstance(resource, Repo):
                repositories.append(resource)
                path = Path(resource.working_dir)
            else:
                path = Path(resource)
            directories.append(path)
            (path / "locked").touch()
            (path / "removable").touch()
        return "passed"

    assert case(SimpleNamespace(rorepo=source_repo)) == "passed"
    assert os.getcwd() == previous_cwd
    assert directories
    for directory in directories:
        assert (directory / "locked").exists()
        assert not (directory / "removable").exists()
    for repo in repositories:
        assert repo._gix_repository is None


def test_directory_decorator_preserves_failed_test_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup.tempfile, "tempdir", str(tmp_path))
    error = AssertionError("test body failed")
    directories = []

    @with_rw_directory
    def case(self, directory):
        directories.append(Path(directory))
        Path(directory, "evidence").write_text("keep", encoding="utf-8")
        raise error

    with pytest.raises(AssertionError) as caught:
        case(None)

    assert caught.value is error
    assert (directories[0] / "evidence").read_text(encoding="utf-8") == "keep"
