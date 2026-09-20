"""High-level operands must not become Git options."""

from unittest import mock

import pytest

from git import Actor, Git, GitCommandError, Head, Remote, RemoteReference, Repo, TagReference
from git.exc import UnsafeOptionError


@pytest.mark.parametrize("allow_unsafe_options", [False, True])
@pytest.mark.parametrize(
    "refspec",
    ["--upload-pack=helper", ["--upl=helper"], ["main", "--dry-run"], "-uhelper", "--arg value", "--"],
)
def test_pull_rejects_option_shaped_refspec(tmp_path, refspec, allow_unsafe_options):
    repo = Repo.init(tmp_path)
    remote = Remote(repo, "origin")
    with mock.patch.object(Git, "_call_process", side_effect=AssertionError("Git must not run")) as run:
        with pytest.raises(UnsafeOptionError):
            remote.pull(refspec, allow_unsafe_options=allow_unsafe_options)
        run.assert_not_called()


def test_pull_rejects_option_shaped_remote(tmp_path):
    repo = Repo.init(tmp_path)
    remote = Remote(repo, "--upload-pack=helper")
    with mock.patch.object(Git, "_call_process", side_effect=AssertionError("Git must not run")) as run:
        with pytest.raises(UnsafeOptionError):
            remote.pull("main")
        run.assert_not_called()


def test_pull_preserves_operand_and_explicit_option_values(tmp_path):
    repo = Repo.init(tmp_path)
    remote = Remote(repo, "origin")
    with mock.patch.object(Git, "_call_process") as run, mock.patch.object(
        Remote, "_get_fetch_info_from_stderr", return_value=[]
    ):
        remote.pull("refs/heads/topic", upload_pack="helper with spaces", allow_unsafe_options=True)
    assert run.call_args[0] == ("pull", "--", remote, ["refs/heads/topic"])
    assert run.call_args[1]["upload_pack"] == "helper with spaces"


def test_delete_head_cannot_override_force(tmp_path):
    repo = Repo.init(tmp_path)
    actor = Actor("Test", "test@example.com")
    initial = repo.index.commit("initial", author=actor, committer=actor)
    branch = repo.create_head("unmerged", initial)
    branch.commit = repo.index.commit("unmerged", head=False, author=actor, committer=actor)
    with pytest.raises(GitCommandError):
        repo.delete_head("--force", branch, force=False)
    assert branch.is_valid()
    repo.delete_head(branch, force=True)
    assert not branch.is_valid()


def test_rename_head_cannot_select_current_branch(tmp_path):
    repo = Repo.init(tmp_path)
    actor = Actor("Test", "test@example.com")
    repo.index.commit("initial", author=actor, committer=actor)
    original = repo.active_branch.name
    with pytest.raises(GitCommandError):
        Head(repo, "refs/heads/--force").rename("renamed")
    assert repo.active_branch.name == original


def test_tag_operands_follow_option_terminator(tmp_path):
    repo = Repo.init(tmp_path)
    with mock.patch.object(Git, "_call_process") as run:
        TagReference.create(repo, "topic", "HEAD")
        assert run.call_args[0] == ("tag", "--", "topic", "HEAD")
        TagReference.delete(repo, "--list")
        assert run.call_args[0] == ("tag", "-d", "--", "--list")


def test_remote_ref_delete_preserves_operand(tmp_path):
    repo = Repo.init(tmp_path)
    ref = RemoteReference(repo, "refs/remotes/--force")
    with mock.patch.object(Git, "_call_process") as run:
        RemoteReference.delete(repo, ref)
    assert run.call_args[0] == ("branch", "-d", "-r", "--", ref)


def test_move_treats_option_shaped_source_as_filename(tmp_path):
    repo = Repo.init(tmp_path)
    (tmp_path / "--force").write_text("literal source")
    repo.index.add(["--force"])
    assert repo.index.move(["--force", "destination"]) == [("--force", "destination")]
    assert (tmp_path / "destination").read_text() == "literal source"
    assert not (tmp_path / "--force").exists()


def test_move_cannot_override_overwrite_protection(tmp_path):
    repo = Repo.init(tmp_path)
    for name in ("--force", "source", "destination"):
        (tmp_path / name).write_text(name)
    repo.index.add(["--force", "source", "destination"])
    with pytest.raises(GitCommandError):
        repo.index.move(["--force", "source", "destination"])
    assert (tmp_path / "source").read_text() == "source"
    assert (tmp_path / "destination").read_text() == "destination"
    repo.index.move(["source", "destination"], force=True)
    assert (tmp_path / "destination").read_text() == "source"


def test_ignored_treats_option_shaped_path_as_filename(tmp_path):
    repo = Repo.init(tmp_path)
    (tmp_path / ".gitignore").write_text("--verbose\n--arg value\n")
    assert repo.ignored("--verbose", "--arg value") == ["--verbose", "--arg value"]


def test_move_cannot_override_dry_run(tmp_path):
    repo = Repo.init(tmp_path)
    (tmp_path / "source").write_text("source")
    repo.index.add(["source"])
    with pytest.raises(GitCommandError):
        repo.index.move(["--no-dry-run", "source", "destination"], dry_run=True)
    assert (tmp_path / "source").read_text() == "source"
    assert not (tmp_path / "destination").exists()
