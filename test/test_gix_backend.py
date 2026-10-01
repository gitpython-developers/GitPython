"""Exercise the installed backend, including proof that converted calls avoid Git."""

from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest

from git import Git, Repo, _backend
from git.exc import InvalidGitRepositoryError
from gitdb import IStream

gix = pytest.importorskip("gix")


@pytest.fixture(params=["sha1", "sha256"])
def repo(request, tmp_path):
    with Repo.init(tmp_path / "repo", object_format=request.param, initial_branch="main") as repo:
        yield repo


def test_reftable_head_reports_unsupported_storage(repo, tmp_path):
    with Repo.init(tmp_path / "reftable", object_format=repo.object_format, ref_format="reftable") as reftable:
        options = gix.OpenOptions().open_path_as_is(True).bail_if_untrusted(True).strict_config(True)
        native = gix.open_opts(reftable.git_dir, options)
        assert native.config_snapshot().string("extensions.refStorage") == b"reftable"
        # The Rust Unsupported cause is flattened into gix.Error by the bindings.
        with pytest.raises(gix.Error, match="unsupported storage backend"):
            native.head()
        assert reftable.ref_format == "reftable"


def test_native_head_does_not_validate_repository_extensions(repo):
    repo.git.config("core.repositoryFormatVersion", "1")
    repo.git.config("extensions.unknown", "true")
    options = gix.OpenOptions().open_path_as_is(True).bail_if_untrusted(True).strict_config(True)
    assert gix.open_opts(repo.git_dir, options).head().is_unborn()
    # Git's format query also validates extensions; HEAD alone cannot replace it.
    with pytest.raises(InvalidGitRepositoryError):
        Repo(repo.git_dir)


def test_native_worktree_inventory_includes_bare_main(repo, tmp_path):
    with Repo.init(tmp_path / "bare", bare=True, object_format=repo.object_format) as bare:
        linked_path = tmp_path / "linked"
        bare.git.worktree("add", "--orphan", "-b", "linked", str(linked_path))
        bare.git.worktree("lock", "--reason", "keep", str(linked_path))
        with Repo(linked_path) as linked:
            for current in (bare, linked):
                with patch.object(_backend, "gix", None):
                    expected = current.git._call_process_safe("worktree", "list", "--porcelain", "-z")
                with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
                    assert current.git._call_process_safe("worktree", "list", "--porcelain", "-z") == expected


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
        assert repo.git._call_process_safe("rev_parse", "--show-ref-format") == "fallback"
        assert cli.call_count == 3


def test_partial_native_stream_does_not_corrupt_next_read(repo):
    one = repo.odb.store(IStream("blob", 6, BytesIO(b"abcdef"))).binsha
    two = repo.odb.store(IStream("blob", 3, BytesIO(b"xyz"))).binsha
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        stream = repo.odb.stream(one)
        assert stream.read(1) == b"a"
        assert repo.odb.stream(two).read() == b"xyz"
        assert stream.read() == b"bcdef"
