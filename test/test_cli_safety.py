"""Safety and storage-format contracts of library-owned Git plumbing."""

from io import BytesIO
from pathlib import Path
import tempfile
from unittest.mock import PropertyMock, patch

import pytest
from gitdb import IStream
from gitdb.db import LooseObjectDB

from git import Git, Repo
from git.exc import GitCommandError, UnsafeOptionError, UnsupportedOperation
from test.lib.fixtures import fixture_repo, writable_fixture


@pytest.fixture(params=[("sha1", "files"), ("sha1", "reftable"), ("sha256", "files"), ("sha256", "reftable")])
def repo(request):
    scenario = request.node.originalname.removeprefix("test_")
    write = scenario == "default_database_never_uses_python_storage"
    with fixture_repo("safety.sh", scenario, *request.param, write=write) as repo:
        yield repo


@pytest.fixture
def plain_repo(request):
    scenario = (
        "tag_storage_rejects_missing_tagger"
        if request.node.originalname == "test_tag_storage_rejects_missing_tagger"
        else "empty"
    )
    with fixture_repo("safety.sh", scenario, "sha1", "files", write=scenario != "empty") as repo:
        yield repo


@pytest.fixture
def scratch():
    with writable_fixture("safety.sh", "scratch") as fixture:
        yield fixture.path()


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


def test_tag_storage_rejects_missing_tagger(plain_repo):
    repo = plain_repo
    fixture = Path(repo.working_tree_dir).parent
    raw = (fixture / "invalid-tag").read_bytes()
    oid = (fixture / "invalid-tag-id").read_text().strip()
    with pytest.raises(GitCommandError, match="missingTaggerEntry"):
        repo.odb.store(IStream("tag", len(raw), BytesIO(raw)))
    assert not repo.odb.has_object(bytes.fromhex(oid))


def test_batch_queries_cannot_inject_a_second_request(repo):
    payload = b"contents\0\n"
    oid = (Path(repo.working_tree_dir).parent / "blob-id").read_text().strip()
    # A newline is data inside a NUL-framed request, never a second request.
    with pytest.raises(ValueError):
        repo.git.get_object_data(oid + "\n" + oid)
    assert repo.git.get_object_data(oid)[3] == payload
    assert repo.git.get_object_header(oid) == (oid, "blob", len(payload))


@pytest.mark.parametrize("query", ["HEAD\0HEAD", "--batch-all-objects"])
def test_batch_injection_rejected_before_process_start(plain_repo, query):
    repo = plain_repo
    with patch.object(Git, "execute", side_effect=AssertionError("Git must not run")) as execute:
        with pytest.raises(UnsafeOptionError):
            repo.git.get_object_header(query)
        execute.assert_not_called()


@pytest.mark.parametrize("kind,size,data", [("--literally", 0, b""), ("blob", -1, b""), ("blob", 3, b"x")])
def test_invalid_object_stream_does_not_start_git(plain_repo, kind, size, data):
    repo = plain_repo
    with patch.object(Git, "execute", side_effect=AssertionError("Git must not run")) as execute:
        with pytest.raises(ValueError):
            repo.odb.store(IStream(kind, size, BytesIO(data)))
        execute.assert_not_called()


def test_library_calls_reject_shell_and_executable_configuration(plain_repo):
    repo = plain_repo
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


def test_managed_commands_disable_implicit_execution(plain_repo):
    repo = plain_repo
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


def test_blame_and_archive_do_not_run_configured_commands(repo):
    marker = Path(repo.working_tree_dir) / "executed"
    commit = repo.head.commit
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


def test_minimum_git_is_checked_before_creating_repository(scratch):
    destination = scratch / "must-not-exist"
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


def test_removed_object_backend_is_rejected_before_mutation(scratch):
    destination = scratch / "must-not-exist"
    for operation in (
        lambda: Repo(destination, odbt=LooseObjectDB),
        lambda: Repo.init(destination, odbt=LooseObjectDB),
        lambda: Repo.clone_from("unused", destination, odbt=LooseObjectDB),
    ):
        with patch.object(Git, "execute", side_effect=AssertionError("Git must not run")):
            with pytest.raises(ValueError, match="GitCmdObjectDB"):
                operation()
        assert not destination.exists()


def test_paths_use_literal_environment_syntax_and_expand_tilde(scratch, monkeypatch):
    from git.util import expand_path

    monkeypatch.setenv("GITPYTHON_LITERAL_PATH", "expanded")
    monkeypatch.setenv("HOME", str(scratch))
    monkeypatch.setenv("USERPROFILE", str(scratch))
    assert Path(expand_path("~/repo")) == scratch / "repo"
    assert Path(expand_path(Path("~/repo"))) == scratch / "repo"
    for name in ("$GITPYTHON_LITERAL_PATH", "%GITPYTHON_LITERAL_PATH%"):
        destination = scratch / name
        with Repo.init(destination) as repo:
            assert Path(repo.working_tree_dir) == destination
        assert Git.polish_url(name, is_cygwin=False) == name
