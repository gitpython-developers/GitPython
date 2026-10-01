"""Exercise the installed backend, including proof that converted calls avoid Git."""

from io import BytesIO
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

from git import Actor, Commit, Git, Reference, Repo, _backend
from git.exc import GitCommandError
from gitdb import IStream

gix = pytest.importorskip("gix")


@pytest.fixture(params=["sha1", "sha256"])
def repo(request, tmp_path):
    with Repo.init(tmp_path / "repo", object_format=request.param, initial_branch="main") as repo:
        yield repo


def test_native_objects_trees_commits_and_index_reads(repo):
    actor = Actor("Example", "example@example.invalid")
    paths = ["file", "dir/with space", "dir/unicode-é", "--option"]
    for name in paths:
        path = Path(repo.working_dir, name)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(name.encode())
    index = repo.index
    # All setup has finished; these operations must succeed without a subprocess.
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        index.add(paths)
        tree = index.write_tree()
        assert {blob.path for blob in tree.traverse() if blob.type == "blob"} == set(paths)
        assert tree["file"].data_stream.read() == b"file"
        assert set(repo.index.entries) == {(name, 0) for name in paths}
        stream = IStream("blob", 4, BytesIO(b"data"))
        assert repo.odb.store(stream) is stream
        assert repo.odb.stream(stream.binsha).read(2) == b"da"
    commit = index.commit("message without a trailing newline", author=actor, committer=actor, skip_hooks=True)
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        assert repo.commit(commit.hexsha).message == "message without a trailing newline"
        assert repo.merge_base(commit, commit) == [commit]
        assert repo.is_ancestor(commit, commit)
        assert commit.replace(message="changed").message == "changed"


def test_native_tree_and_commit_bytes_match_cli(repo):
    actor = Actor("Example", "example@example.invalid")
    Path(repo.working_dir, "file").write_bytes(b"payload\n")
    index = repo.index
    index.add(["file"])
    native_tree = index.write_tree()
    commit = index.commit("message", author=actor, committer=actor, skip_hooks=True)
    native = commit.replace(message="a changed message")
    with patch.object(_backend, "gix", None):
        assert index.write_tree().hexsha == native_tree.hexsha
        assert commit.replace(message="a changed message").hexsha == native.hexsha


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


def test_native_command_queries_match_cli(repo):
    Path(repo.working_dir, "file").write_bytes(b"content")
    repo.index.add(["file"])
    commit = repo.index.commit("initial", skip_hooks=True)
    repo.git.update_environment(
        GIT_COMMITTER_NAME="Example",
        GIT_COMMITTER_EMAIL="example@example.invalid",
        GIT_COMMITTER_DATE="1100000000 -0430",
    )
    with repo.config_writer() as writer:
        writer.set_value("test", "value", "configured")
    queries = [
        ("rev_parse", "--verify", "--end-of-options", "HEAD"),
        ("rev_parse", "--path-format=absolute", "--git-common-dir"),
        ("rev_parse", "--is-bare-repository"),
        ("rev_parse", "--show-object-format"),
        ("rev_parse", "--show-ref-format"),
        ("rev_parse", "--show-toplevel"),
        ("ls_tree", "-z", "--full-tree", commit.tree.hexsha),
        ("symbolic_ref", "--quiet", "--no-recurse", "--", "HEAD"),
        ("for_each_ref", "--format=%(refname)", "--", "refs/heads"),
        ("config", "--get", "test.value"),
        ("worktree", "list", "--porcelain", "-z"),
        ("merge_base", "--", commit.hexsha, commit.hexsha),
        ("ls_files", "--stage", "-v", "-z", "--full-name"),
        ("update_index", "--show-index-version"),
        ("reflog", "exists", "--", "HEAD"),
        ("var", "GIT_COMMITTER_IDENT"),
    ]
    for method, *args in queries:
        with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call: " + method)):
            native = repo.git._call_process_safe(method, *args, stdout_as_string=False)
        with patch.object(_backend, "gix", None):
            assert native == repo.git._call_process_safe(method, *args, stdout_as_string=False)


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


@pytest.mark.parametrize("mode,kind", [("100644", "blob"), ("040000", "tree"), ("160000", "commit")])
def test_tree_writes_validate_child_object_kinds(repo, mode, kind):
    commit = repo.index.commit("initial", skip_hooks=True)
    blob = repo.odb.store(IStream("blob", 1, BytesIO(b"x")))
    wrong_id = blob.hexsha.decode() if kind == "commit" else commit.hexsha
    with tempfile.TemporaryFile() as stream:
        stream.write((mode + " " + kind + " " + wrong_id + "\twrong\0").encode())
        stream.seek(0)
        with pytest.raises(GitCommandError):
            repo.git._call_process_safe("mktree", "-z", "--missing", istream=stream)


def test_commit_identity_cleanup_matches_git(repo):
    actor = Actor(" Name. ", " email@example.invalid ")
    tree = repo.index.write_tree()
    kwargs = {
        "author": actor,
        "committer": actor,
        "author_date": "1100000000 +0000",
        "commit_date": "1100000000 +0000",
        "parent_commits": [],
    }
    commit = Commit.create_from_tree(repo, tree, "message", **kwargs)
    with patch.object(_backend, "gix", None):
        assert commit == Commit.create_from_tree(repo, tree, "message", **kwargs)


def test_symbolic_alias_cannot_point_a_branch_at_a_blob(repo):
    commit = repo.index.commit("initial", skip_hooks=True)
    blob = repo.odb.store(IStream("blob", 1, BytesIO(b"x")))
    repo.git.symbolic_ref("refs/aliases/main", "refs/heads/main")
    alias = Reference(repo, "refs/aliases/main")
    with pytest.raises(GitCommandError):
        alias.set_object(blob.hexsha.decode())
    assert repo.head.commit == commit


def test_partial_native_stream_does_not_corrupt_next_read(repo):
    one = repo.odb.store(IStream("blob", 6, BytesIO(b"abcdef"))).binsha
    two = repo.odb.store(IStream("blob", 3, BytesIO(b"xyz"))).binsha
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        stream = repo.odb.stream(one)
        assert stream.read(1) == b"a"
        assert repo.odb.stream(two).read() == b"xyz"
        assert stream.read() == b"bcdef"


def test_native_history_and_references(repo):
    repo.git.update_environment(
        GIT_COMMITTER_NAME="Reflog Actor",
        GIT_COMMITTER_EMAIL="actor@example.invalid",
        GIT_COMMITTER_DATE="1100000000 -0430",
    )
    first = repo.index.commit("first", skip_hooks=True)
    second = first.replace(message="second", parents=[first])
    branch = repo.create_head("other", first)
    repo.heads  # Warm the existing, Git-validated reference-name cache.
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        repo.head.set_object(second, "through\tHEAD")
        branch.set_object(second, "inactive branch")
        assert first.count() == 1
        assert second.count() == 2
        assert list(repo.iter_commits(first_parent=True, skip=1)) == [first]
        assert list(repo.iter_commits(max_count=1)) == [second]
        assert repo.head.log_entry(-1).message == "through HEAD"
        assert branch.log_entry(-1).newhexsha == second.hexsha
        native_log = repo.head.log()
        native_refs = [ref.path for ref in repo.heads]
    with patch.object(_backend, "gix", None):
        assert native_log == repo.head.log()
        assert native_refs == [ref.path for ref in repo.heads]


def test_native_raw_diff_matches_cli(repo):
    for name, content in (("a", b"rename me\n"), ("dir/b", b"old\n"), ("removed", b"gone\n")):
        path = Path(repo.working_dir, name)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
    repo.index.add(["a", "dir", "removed"])
    before = repo.index.commit("before", skip_hooks=True)
    Path(repo.working_dir, "a").rename(Path(repo.working_dir, "z"))
    Path(repo.working_dir, "dir/b").write_bytes(b"changed\n")
    repo.git.add("--all")
    after = repo.index.commit("after", skip_hooks=True)
    for options in ({}, {"R": True}, {"no_renames": True}):
        with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
            native = before.diff(after, **options)
        with patch.object(_backend, "gix", None):
            assert native == before.diff(after, **options)
