"""Exercise the installed backend, including proof that converted calls avoid Git."""

from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest

from git import Git, Repo, _backend
from git.exc import GitCommandError
from gitdb import IStream

gix = pytest.importorskip("gix")


@pytest.fixture(params=["sha1", "sha256"])
def repo(request, tmp_path):
    with Repo.init(tmp_path / "repo", object_format=request.param, initial_branch="main") as repo:
        yield repo


def test_unknown_command_and_storage_environment_use_cli(repo):
    before = _backend.statistics()
    assert repo.git._call_process_safe("status", "--porcelain") == ""
    assert _backend.statistics()["status", "CLI: not converted"] > before.get(("status", "CLI: not converted"), 0)
    with repo.git.custom_environment(GIT_OBJECT_DIRECTORY=str(Path(repo.common_dir, "objects"))):
        with patch.object(Git, "execute", return_value="fallback") as cli:
            assert repo.git._call_process_safe("rev_parse", "--verify", "--end-of-options", "HEAD") == "fallback"
            cli.assert_called_once()
    with patch.object(Git, "execute", return_value="fallback") as cli:
        assert repo.git._call_process_safe("for_each_ref", "--format=%(refname)", "--", "refs/*") == "fallback"
        with repo.git.custom_environment(GIT_INDEX_FILE=".git/index"):
            assert repo.git._call_process_safe("ls_files", "--stage", "-v", "-z", "--full-name") == "fallback"
        assert cli.call_count == 2


def test_a_native_write_failure_is_not_retried(repo, monkeypatch):
    attempts = []

    def fail():
        attempts.append("write")
        raise gix.Error("write failed after it began")

    def handler(native, args, kwargs):
        return _backend._write("test_write", fail)

    monkeypatch.setitem(_backend._HANDLERS, "test_write", handler)
    with patch.object(Git, "execute", side_effect=AssertionError("must not retry through CLI")):
        with pytest.raises(GitCommandError, match="write failed after it began"):
            repo.git._call_process_safe("test_write")
    assert attempts == ["write"]


def test_partial_native_stream_does_not_corrupt_next_read(repo):
    one = repo.odb.store(IStream("blob", 6, BytesIO(b"abcdef"))).binsha
    two = repo.odb.store(IStream("blob", 3, BytesIO(b"xyz"))).binsha
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        stream = repo.odb.stream(one)
        assert stream.read(1) == b"a"
        assert repo.odb.stream(two).read() == b"xyz"
        assert stream.read() == b"bcdef"
