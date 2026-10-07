"""Safety and storage-format contracts of library-owned Git plumbing."""

from io import BytesIO
from pathlib import Path
import shlex
import tempfile
from unittest.mock import PropertyMock, patch

import pytest
from gitdb import IStream
from gitdb.db import LooseObjectDB

from git import Actor, Git, Repo
from git.exc import UnsafeOptionError, UnsupportedOperation


@pytest.fixture(params=[("sha1", "files"), ("sha1", "reftable"), ("sha256", "files"), ("sha256", "reftable")])
def repo(tmp_path, request):
    object_format, ref_format = request.param
    with Repo.init(tmp_path / "repo", object_format=object_format, ref_format=ref_format) as repo:
        yield repo


def test_default_database_never_uses_python_storage(repo):
    payload = b"binary\0payload\n"
    with patch.object(LooseObjectDB, "store", side_effect=AssertionError("Python storage used")):
        stored = repo.odb.store(IStream("blob", len(payload), BytesIO(payload)))
    assert len(stored.binsha) == repo._oid_size
    assert repo.odb.info(stored.binsha).type == b"blob"
    assert repo.odb.stream(stored.binsha).read() == payload
    assert repo.odb.has_object(stored.binsha)
    assert stored.binsha in list(repo.odb.sha_iter())
    assert not repo.odb.has_object(bytes(repo._oid_size))


def test_batch_queries_cannot_inject_a_second_request(repo):
    payload = b"contents\0\n"
    stored = repo.odb.store(IStream("blob", len(payload), BytesIO(payload)))
    oid = stored.binsha.hex()
    # A newline is data inside a NUL-framed request, never a second request.
    with pytest.raises(ValueError):
        repo.git.get_object_data(oid + "\n" + oid)
    assert repo.git.get_object_data(oid)[3] == payload
    assert repo.git.get_object_header(oid) == (oid, "blob", len(payload))


@pytest.mark.parametrize("query", ["HEAD\0HEAD", "--batch-all-objects"])
def test_batch_injection_rejected_before_process_start(repo, query):
    with patch.object(Git, "execute", side_effect=AssertionError("Git must not run")) as execute:
        with pytest.raises(UnsafeOptionError):
            repo.git.get_object_header(query)
        execute.assert_not_called()


@pytest.mark.parametrize("kind,size,data", [("--literally", 0, b""), ("blob", -1, b""), ("blob", 3, b"x")])
def test_invalid_object_stream_does_not_start_git(repo, kind, size, data):
    with patch.object(Git, "execute", side_effect=AssertionError("Git must not run")) as execute:
        with pytest.raises(ValueError):
            repo.odb.store(IStream(kind, size, BytesIO(data)))
        execute.assert_not_called()


def test_library_calls_reject_shell_and_executable_configuration(repo):
    with patch.object(Git, "execute", side_effect=AssertionError("Git must not run")) as execute:
        for options in (
            {"shell": True},
            {"_config": ["core.sshCommand=unexpected"]},
            {"_config": ["trailer.custom.cmd="]},
            {"_allow_hooks": True},
        ):
            with pytest.raises(UnsafeOptionError):
                repo.git._call_process_safe("status", **options)
        execute.assert_not_called()


def test_managed_commands_disable_implicit_execution(repo):
    repo.git.version_info
    with patch.object(Git, "execute", return_value="") as execute:
        repo.git._call_process_safe("status")
    command = execute.call_args.args[0]
    assert command[1:3] == ["--no-pager", "--no-optional-locks"]
    assert "core.fsmonitor=false" in command
    assert "gc.auto=0" in command
    assert "maintenance.auto=false" in command
    assert any(option.startswith("core.hooksPath=") for option in command)
    assert execute.call_args.kwargs["shell"] is False
    assert execute.call_args.kwargs["env"]["GIT_NO_LAZY_FETCH"] == "1"


def test_blame_and_archive_do_not_run_configured_commands(repo, tmp_path):
    marker = tmp_path / "executed"
    script = tmp_path / "unexpected-command"
    script.write_text("#!/bin/sh\nprintf executed > " + shlex.quote(str(marker)) + "\ncat\n")
    script.chmod(0o755)
    command = "sh " + shlex.quote(str(script))
    worktree = Path(repo.working_tree_dir)
    (worktree / "file").write_text("original\n")
    (worktree / ".gitattributes").write_text("file diff=unexpected\n")
    repo.index.add(["file", ".gitattributes"])
    actor = Actor("Tests", "tests@example.invalid")
    commit = repo.index.commit("initial", author=actor, committer=actor, skip_hooks=True)
    with repo.config_writer() as config:
        config.set_value('diff "unexpected"', "textconv", command)
        for name in ("custom", "tgz", "tar.gz"):
            config.set_value('tar "' + name + '"', "command", command)
    assert repo.blame("HEAD", "file")[0][1] == ["original"]
    assert list(repo.blame_incremental("HEAD", "file"))
    for options in ({"textconv": True}, {"rev_opts": ["--textconv"]}):
        with pytest.raises(UnsafeOptionError):
            repo.blame("HEAD", "file", **options)
    for allow_unsafe_options in (False, True):
        with pytest.raises(UnsafeOptionError):
            commit.diff(
                None,
                create_patch=True,
                textconv=True,
                insert_kwargs_after="--no-textconv",
                allow_unsafe_options=allow_unsafe_options,
            )
    with tempfile.TemporaryFile() as archive:
        for archive_format in ("tar", "zip", "tgz", "tar.gz"):
            repo.archive(archive, format=archive_format)
        for options in ({"format": "custom"}, {"forma": ["tar", "custom"]}):
            with pytest.raises(UnsafeOptionError):
                repo.archive(archive, **options)
    assert not marker.exists()


def test_minimum_git_is_checked_before_creating_repository(tmp_path):
    destination = tmp_path / "must-not-exist"
    with patch.object(Git, "version_info", new_callable=PropertyMock, return_value=(2, 51, 1)):
        with pytest.raises(UnsupportedOperation, match="2.52"):
            Repo.init(destination)
    assert not destination.exists()


def test_raw_command_interface_keeps_its_passthrough_contract():
    with patch.object(Git, "execute", return_value="raw") as execute:
        assert Git().custom_command("--arbitrary", setting="value") == "raw"
    assert execute.call_args.args[0] == [
        Git.GIT_PYTHON_GIT_EXECUTABLE,
        "custom-command",
        "--setting=value",
        "--arbitrary",
    ]
