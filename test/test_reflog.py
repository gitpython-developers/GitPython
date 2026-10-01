# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import pytest

from git import Actor, Repo
from git.exc import GitCommandError, UnsafeOptionError
from git.refs import RefLog, RefLogEntry, SymbolicReference


@pytest.fixture(params=[("sha1", "files"), ("sha256", "files"), ("sha1", "reftable"), ("sha256", "reftable")])
def repo(request, tmp_path):
    object_format, ref_format = request.param
    with Repo.init(tmp_path, object_format=object_format, ref_format=ref_format) as repo:
        repo.git.update_environment(
            GIT_AUTHOR_NAME="Commit Author",
            GIT_AUTHOR_EMAIL="author@example.invalid",
            GIT_COMMITTER_NAME="First Committer",
            GIT_COMMITTER_EMAIL="first@example.invalid",
            GIT_AUTHOR_DATE="1000000000 +0000",
            GIT_COMMITTER_DATE="1000000001 +0130",
        )
        repo.git.commit("--no-gpg-sign", "--allow-empty", "-m", "initial")
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


def test_reference_transactions_and_discovery(repo, tmp_path):
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

    worktree = tmp_path / "linked"
    repo.git.worktree("add", "--detach", str(worktree), second.hexsha)
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


def test_tag_creation_requires_signing_opt_in(repo, tmp_path):
    marker = tmp_path / "signed"
    signer = tmp_path / "signer"
    signer.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 1\n")
    signer.chmod(0o755)
    repo.git.config("gpg.program", str(signer))
    repo.git.config("tag.gpgSign", "true")
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
    branch = repo.create_head('quoted"branch')
    with branch.config_writer() as config:
        config.set_value("description", "retained")
    assert branch.config_reader().get_value("description") == "retained"
    branch.rename('renamed"branch')
    assert branch.config_reader().get_value("description") == "retained"
    assert repo.git.config("get", 'branch.renamed"branch.description') == "retained"
