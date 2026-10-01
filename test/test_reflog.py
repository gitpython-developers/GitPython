# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import sys
from pathlib import Path

import pytest

from git import Actor, Repo
from git.exc import GitCommandError, UnsafeOptionError
from git.refs import RefLog, RefLogEntry, SymbolicReference
from test.lib.fixtures import fixture_repo


@pytest.fixture(params=[("sha1", "files"), ("sha256", "files"), ("sha1", "reftable"), ("sha256", "reftable")])
def repo(request):
    name = request.node.originalname.removeprefix("test_")
    scenario = (
        name if name in {"reference_transactions_and_discovery", "tag_creation_requires_signing_opt_in"} else "initial"
    )
    # Linked-worktree administrative files record the final absolute paths.
    execute = scenario == "reference_transactions_and_discovery"
    with fixture_repo("reflog.sh", scenario, *request.param, write=True, execute=execute) as repo:
        yield repo


def test_native_reflog_entry_fields_and_append(repo):
    commit = repo.head.commit
    original = repo.head.log()
    assert isinstance(original, RefLog)
    assert original[-1].newhexsha == commit.hexsha
    assert original[-1].actor == Actor("First Committer", "first@example.invalid")
    assert original[-1].time == (1000000001, -5400)
    assert not hasattr(original[-1], "oldhexsha")

    repo.git.update_environment(
        GIT_COMMITTER_NAME="Reflog Actor",
        GIT_COMMITTER_EMAIL="log@example.invalid",
        GIT_COMMITTER_DATE="1100000000 -0430",
    )
    entry = repo.head.log_append(repo._null_binsha, "message\twith  spaces\nignored", commit.binsha)
    assert isinstance(entry, RefLogEntry)
    assert entry.newhexsha == commit.hexsha
    assert entry.actor == Actor("Reflog Actor", "log@example.invalid")
    assert entry.time == (1100000000, 16200)
    assert entry.message == "message with spaces"
    assert repo.head.log_entry(-1) == entry
    assert repo.head.log_entry(0) == original[0]
    assert len(original) + 1 == len(repo.head.log())
    with pytest.raises(IndexError):
        repo.head.log_entry(10000)


def test_reflog_backend_and_input_safety(repo):
    before = repo.head.log()
    with pytest.raises(ValueError):
        repo.head.log_append(b"short", "invalid", repo.head.commit.binsha)
    with pytest.raises(ValueError):
        repo.head.log_append(repo._null_binsha, "bad\0message", repo.head.commit.binsha)
    with pytest.raises((ValueError, UnsafeOptionError)):
        SymbolicReference(repo, "--all").log()
    with pytest.raises(ValueError):
        SymbolicReference(repo, "../../outside").log_append(repo._null_binsha, "invalid", repo.head.commit.binsha)
    assert repo.head.log() == before
    assert SymbolicReference(repo, "refs/heads/no-log").log() == []
    with pytest.raises(GitCommandError):
        repo.head.log_append(repo._null_binsha, "missing object", b"\xff" * repo._oid_size)


def test_reference_transactions_and_discovery(repo):
    first = repo.head.commit
    branch = repo.create_head("other", first)
    repo.head.set_reference(branch)
    repo.git.commit("--no-gpg-sign", "--allow-empty", "-m", "second")
    second = repo.head.commit
    repo.head.set_object(first, "through HEAD")
    assert branch.commit == first
    assert repo.head.log_entry(-1).newhexsha == first.hexsha
    assert branch.log_entry(-1).message == "through HEAD"

    symbol = SymbolicReference.create(repo, "refs/custom/link", branch, logmsg="symbol")
    assert symbol.reference == branch
    symbol.rename("refs/custom/renamed")
    assert symbol.reference == branch
    SymbolicReference.delete(repo, symbol.path)
    assert not symbol.is_valid()
    branch.rename("renamed")
    assert repo.head.reference == branch
    assert branch in repo.heads

    worktree = Path(repo.working_tree_dir).parent / "linked"
    linked = Repo(worktree)
    try:
        for location in (repo.working_tree_dir, repo.git_dir, worktree, linked.git_dir):
            with Repo(location) as reopened:
                assert reopened.object_format == repo.object_format
                assert reopened.ref_format == repo.ref_format
                assert reopened._oid_size == len(first.binsha)
                assert reopened._null_hexsha == "0" * len(first.hexsha)
                assert reopened.working_tree_dir is not None
                assert reopened.head.commit in (first, second)
    finally:
        linked.close()


def test_tag_creation_requires_signing_opt_in(repo):
    marker = Path(repo.working_tree_dir) / "signed"
    tag = repo.create_tag("unsigned", message="ordinary annotated tag")
    assert tag.commit == repo.head.commit
    assert not marker.exists()
    for option in (
        {"s": True},
        {"sign": True},
        {"u": "identity"},
        {"verify": True},
        {"edit": True},
        {"trailer": "Key: value"},
    ):
        with pytest.raises(UnsafeOptionError):
            repo.create_tag("unsafe", **option)
    assert not marker.exists()


def test_checkout_and_reset_reject_interactive_patch_helpers(repo):
    branch = repo.active_branch
    before = repo.head.commit
    for operation in (branch.checkout, repo.head.reset):
        for option in ({"patch": True}, {"pat": True}, {"p": True}):
            with pytest.raises(UnsafeOptionError):
                operation(**option)
    assert repo.head.commit == before


def test_quoted_branch_configuration_survives_rename(repo):
    if sys.platform == "win32" and repo.ref_format == "files":
        # Loose references need filenames that Windows cannot represent.
        with pytest.raises(OSError, match="Could not create reference") as error:
            repo.create_head('quoted"branch')
        assert isinstance(error.value.__cause__, GitCommandError)
        return
    branch = repo.create_head('quoted"branch')
    with branch.config_writer() as config:
        config.set_value("description", "retained")
    assert branch.config_reader().get_value("description") == "retained"
    branch.rename('renamed"branch')
    assert branch.config_reader().get_value("description") == "retained"
    assert repo.git.config("get", 'branch.renamed"branch.description') == "retained"
