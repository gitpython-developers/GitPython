# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Cleanup failures must not fail, skip, or hide the result of a test."""

from contextlib import nullcontext, suppress
import errno
import gc
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import weakref

import pytest

from git import Repo
from git.util import rmtree
from test import cleanup
from test.cleanup import TemporaryDirectory, cleanup_directory
from test.lib import requires_symlinks, with_rw_and_rw_remote_repo, with_rw_directory, with_rw_repo
from test.lib.helper import git_daemon_launched
from test.lib.fixtures import fixture_repo, writable_fixture
from test.lib import fixtures


@pytest.fixture
def cleanup_root(request):
    # The symlink fixture must run in its final location; native copies dereference links.
    with writable_fixture("cleanup.sh", request.param, execute=request.param == "symlink") as temporary:
        yield temporary.path()


@pytest.fixture
def temporary_directory(cleanup_root, monkeypatch):
    monkeypatch.setattr(cleanup.tempfile, "mkdtemp", lambda **kwargs: str(cleanup_root / "owned"))
    return TemporaryDirectory


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
@pytest.mark.parametrize("cleanup_root", ["nested"], indirect=True)
def test_cleanup_continues_after_locked_file(cleanup_root, locked_file, caplog, monkeypatch, version_info):
    monkeypatch.setattr(cleanup, "sys", SimpleNamespace(platform=sys.platform, version_info=version_info))
    directory = cleanup_root / "owned"
    nested = directory / "nested"

    assert not cleanup_directory(directory)

    assert (nested / "locked").exists()
    assert not (nested / "removable").exists()
    assert not (directory / "removable").exists()
    assert len(caplog.records) == 1
    assert repr(str(directory)) in caplog.text
    assert "file is in use" in caplog.text


@pytest.mark.parametrize("cleanup_root", ["readonly"], indirect=True)
def test_cleanup_removes_readonly_files_and_tolerates_missing_directory(temporary_directory):
    directory = temporary_directory()
    directory.cleanup()
    directory.cleanup()

    assert not Path(directory.name).exists()
    assert cleanup_directory(directory.name)


@requires_symlinks
@pytest.mark.parametrize("locked_link", [False, True])
@pytest.mark.parametrize("cleanup_root", ["symlink"], indirect=True)
def test_cleanup_does_not_touch_symlink_target(cleanup_root, temporary_directory, monkeypatch, locked_link):
    target = cleanup_root / "outside"
    file = target / "readonly"
    mode = file.stat().st_mode
    unlink = os.unlink

    def unlink_unless_locked(path, *args, **kwargs):
        if locked_link and Path(path).name == "link":
            raise PermissionError("link is in use")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink_unless_locked)

    with temporary_directory() as directory:
        assert Path(directory, "link").is_symlink()

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
@pytest.mark.parametrize("cleanup_root", ["locked"], indirect=True)
def test_temporary_directory_preserves_test_body_error(temporary_directory, locked_file, error_type):
    error = error_type("failure in the operation under test")

    with pytest.raises(error_type) as caught:
        with temporary_directory() as directory:
            raise error

    assert caught.value is error
    assert Path(directory, "locked").exists()


@pytest.mark.parametrize("cleanup_root", ["locked"], indirect=True)
def test_implicit_cleanup_is_also_best_effort(temporary_directory, locked_file, caplog):
    directory = temporary_directory()
    path = Path(directory.name)
    reference = weakref.ref(directory)

    del directory
    gc.collect()

    assert reference() is None
    assert (path / "locked").exists()
    assert not (path / "removable").exists()
    assert repr(str(path)) in caplog.text


@pytest.mark.parametrize("cleanup_root", ["locked"], indirect=True)
def test_public_rmtree_remains_strict(cleanup_root, locked_file):
    directory = cleanup_root / "owned"

    with pytest.raises(PermissionError, match="file is in use"):
        rmtree(directory)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows denies removal of a file opened without delete sharing")
@pytest.mark.parametrize("cleanup_root", ["locked"], indirect=True)
def test_real_windows_file_lock_and_explicit_retry(temporary_directory, caplog):
    directory = temporary_directory()
    locked = Path(directory.name, "locked")
    removable = Path(directory.name, "removable")

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
def source_repo():
    with fixture_repo("cleanup.sh", "source", subdir="source") as repo:
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

        # Windows can take just over two seconds to refuse a closed loopback port.
        with pytest.raises(ConnectionRefusedError):
            with socket.create_connection(address, timeout=5):
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


@pytest.mark.parametrize("fail", [False, True])
def test_scripted_fixture_cleanup_keeps_locked_files_without_hiding_result(locked_file, fail):
    error = AssertionError("test body failed")
    expectation = pytest.raises(AssertionError) if fail else nullcontext()
    with expectation as caught:
        with writable_fixture("cleanup.sh", "locked") as temporary:
            root = temporary.path()
            if fail:
                raise error
    assert (root / "owned/locked").exists()
    assert not (root / "owned/removable").exists()
    if fail:
        assert caught.value is error


@pytest.mark.parametrize("copy_fails", [False, True])
def test_failed_fixture_survives_unrenamable_directory_when_copying_is_possible(monkeypatch, caplog, copy_fails):
    error = AssertionError("test body failed")
    paths = []

    @with_rw_directory(script="fixture-lifecycle.sh")
    def case(self, directory):
        paths.append(Path(directory))
        raise error

    def cannot_rename(*args):
        raise PermissionError("directory is in use")

    def cannot_copy(*args, **kwargs):
        raise PermissionError("file cannot be read")

    monkeypatch.setattr(Path, "rename", cannot_rename)
    if copy_fails:
        monkeypatch.setattr(fixtures.shutil, "copytree", cannot_copy)
    with pytest.raises(AssertionError) as caught:
        case(None)
    assert caught.value is error
    retained = paths[0].with_name(paths[0].name + "-retained")
    assert repr(str(retained)) in caplog.text
    if copy_fails:
        assert "Could not copy failed fixture artifacts" in caplog.text
    else:
        assert (retained / "repo/file").read_text() == "initial"
        cleanup_directory(retained)
