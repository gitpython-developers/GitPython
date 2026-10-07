"""Exercise the installed backend, including proof that converted calls avoid Git."""

from io import BytesIO
from pathlib import Path
import pickle
from concurrent.futures import ThreadPoolExecutor
import tempfile
from unittest.mock import patch

import pytest

from git import Actor, Commit, Git, Reference, Repo, _backend
from git.exc import GitCommandError, InvalidGitRepositoryError
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


def test_native_repository_lifetime_and_refresh(repo, tmp_path):
    handle = repo._gix_repository
    assert isinstance(handle, gix.Repository)
    with patch.object(gix, "open_opts", side_effect=AssertionError("unexpected reopen")):
        assert repo.git._call_process_safe("rev_parse", "--show-object-format") == repo.object_format
        assert repo._gix_repository is handle
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(
                pool.map(lambda _: repo.git._call_process_safe("rev_parse", "--show-object-format"), range(2))
            ) == [
                repo.object_format,
                repo.object_format,
            ]
    Path(repo.working_dir, "file").write_text("payload")
    repo.index.add(["file"])
    first = repo.index.commit("native", skip_hooks=True)
    assert repo.commit().hexsha == first.hexsha
    repo.git.commit("--allow-empty", "-m", "CLI", "--no-verify")
    assert repo.commit().message == "CLI\n"
    assert repo._gix_repository is handle
    assert set(repo.index.entries) == {("file", 0)}

    with repo.config_writer() as writer:
        writer.set_value("core", "abbrev", "9")
    assert _backend._repository(repo.git, {}).config_snapshot().integer("core.abbrev") == 9
    assert repo._gix_repository is handle
    include = tmp_path / "included"
    include.write_text("[test]\nvalue = first\n")
    repo.git.config("include.path", str(include))
    assert _backend._repository(repo.git, {}).config_snapshot().string("test.value") == b"first"
    include.write_text("[test]\nvalue = second\n")
    assert _backend._repository(repo.git, {}).config_snapshot().string("test.value") == b"second"

    with pickle.loads(pickle.dumps(repo)) as restored:
        assert restored._gix_repository is None
        assert restored.commit().hexsha == repo.commit().hexsha
        assert restored._gix_repository is not None
    repo.close()
    assert repo._gix_repository is None
    assert repo.commit().message == "CLI\n"
    assert repo._gix_repository is not handle


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
        assert repo.git._call_process_safe("rev_parse", "--show-ref-format") == "fallback"
        assert cli.call_count == 3


def test_compatibility_object_format_uses_cli_before_writing(repo):
    repo.git.config("core.repositoryFormatVersion", "1")
    repo.git.config("extensions.compatObjectFormat", "sha256" if repo.object_format == "sha1" else "sha1")
    # Check dispatch without requiring Git's optional compatibility-hash support.
    with patch.object(_backend, "_write", side_effect=AssertionError("unexpected native mutation")):
        with patch.object(Git, "execute", return_value="fallback") as cli:
            assert repo.git._call_process_safe("rev_parse", "--show-object-format") == "fallback"
            assert (
                repo.git._call_process_safe("hash_object", "-t", "blob", "-w", "--stdin", istream=BytesIO(b"content"))
                == "fallback"
            )
            assert cli.call_count == 2


def test_native_command_queries_match_cli(repo, monkeypatch):
    Path(repo.working_dir, "file").write_bytes(b"content")
    repo.index.add(["file"])
    commit = repo.index.commit("initial", skip_hooks=True)
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Example")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "example@example.invalid")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "1100000000 -0430")
    with repo.config_writer() as writer:
        writer.set_value("test", "value", "configured")
    queries = [
        ("rev_parse", "--verify", "--end-of-options", "HEAD"),
        ("rev_parse", "--path-format=absolute", "--git-common-dir"),
        ("rev_parse", "--is-bare-repository"),
        ("rev_parse", "--show-object-format"),
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


@pytest.mark.parametrize("fields", [("NAME",), ("EMAIL",), ("DATE",), ("NAME", "EMAIL", "DATE")])
def test_per_command_committer_identity_uses_cli(repo, fields, monkeypatch):
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Process")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "process@example.invalid")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "1000000000 +0000")
    values = {"NAME": "Override", "EMAIL": "override@example.invalid", "DATE": "1100000000 -0430"}
    env = {"GIT_COMMITTER_" + field: values[field] for field in fields}
    with patch.object(_backend, "gix", None):
        expected = repo.git._call_process_safe("var", "GIT_COMMITTER_IDENT", env=env)
    with patch.object(Git, "execute", autospec=True, side_effect=Git.execute) as cli:
        assert repo.git._call_process_safe("var", "GIT_COMMITTER_IDENT", env=env) == expected
        assert cli.call_count == 1


def test_reference_enumeration_preserves_aliases_and_skips_dangling_refs(repo):
    repo.index.commit("initial", skip_hooks=True)
    repo.git.symbolic_ref("refs/heads/alias", "refs/heads/main")
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        assert repo.git._call_process_safe("for_each_ref", "--format=%(refname)", "--", "refs/heads") == (
            "refs/heads/alias\nrefs/heads/main"
        )
    repo.git.symbolic_ref("refs/heads/dangling", "refs/heads/missing")
    with patch.object(_backend, "gix", None):
        expected = [ref.path for ref in repo.heads]
    assert [ref.path for ref in repo.heads] == expected == ["refs/heads/alias", "refs/heads/main"]


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


def test_native_history_and_references(repo, monkeypatch):
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Reflog Actor")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "actor@example.invalid")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "1100000000 -0430")
    first = repo.index.commit("first", skip_hooks=True)
    second = first.replace(message="second", parents=[first])
    branch = repo.create_head("other", first)
    repo.heads  # Warm the existing, Git-validated reference-name cache.
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        repo.head.set_object(second, "through HEAD")
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


def test_native_refedit_message_is_verbatim(repo):
    commit = repo.index.commit("initial", skip_hooks=True)
    native = gix.open(repo.git_dir)
    log = gix.LogChange()
    log.force_create_reflog = True
    log.message = "  keep\t  spaces  "
    edit = gix.RefEdit.update_with_log(
        "refs/heads/native", gix.Target.Object(gix.ObjectId(commit.hexsha)), gix.PreviousValue.Any, log
    )
    native.edit_references_as([edit], gix.Signature("Example", "example@example.invalid", 1100000000, 0))
    with native.find_reference("refs/heads/native").log_iter().rev() as lines:
        assert next(lines).message == b"  keep\t  spaces  "
    with patch.object(_backend, "gix", None):
        repo.git._call_process_safe(
            "update_ref", "--create-reflog", "-m", "  keep\t  spaces  ", "--", "refs/heads/control", commit.hexsha
        )
    with native.find_reference("refs/heads/control").log_iter().rev() as lines:
        assert next(lines).message == b"keep spaces"


@pytest.mark.parametrize("message", ["through\tHEAD", " leading  spaces ", "line\nnext", "mixed\r\v\fspaces"])
def test_reflog_message_cleanup_uses_cli_before_mutation(repo, message, monkeypatch):
    monkeypatch.setenv("GIT_COMMITTER_DATE", "1100000000 -0430")
    first = repo.index.commit("first", skip_hooks=True)
    second = first.replace(message="second", parents=[first])
    branch = repo.create_head("other", first)
    control = repo.create_head("control", first)
    args = ("--create-reflog", "-m", message, "--")
    with patch.object(_backend, "_write", side_effect=AssertionError("must fall back before mutation")):
        with patch.object(Git, "execute", autospec=True, side_effect=Git.execute) as cli:
            repo.git._call_process_safe("update_ref", *args, branch.path, second.hexsha)
            assert cli.call_count == 1
    native_log = branch.log_entry(-1)
    with patch.object(_backend, "gix", None):
        repo.git._call_process_safe("update_ref", *args, control.path, second.hexsha)
        assert native_log == control.log_entry(-1)


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


def test_native_status_and_ignore_match_cli_without_writing_index(repo):
    root = Path(repo.working_dir)
    (root / ".gitignore").write_text("*.log\nignored/\n")
    (root / "tracked.log").write_text("tracked even though ignored\n")
    repo.index.add([".gitignore", "tracked.log"])
    repo.index.commit("initial", skip_hooks=True)
    (root / "ignored").mkdir()
    (root / "ignored/file").write_text("ignored")
    (root / "untracked\nfile").write_text("untracked")
    (root / "tracked.log").write_text("changed")
    Repo.init(root / "nested").close()
    paths = ["ignored", "ignored/file", "new.log", "tracked.log", "untracked\nfile"]
    index_before = Path(repo.index.path).read_bytes()
    options = [{}, {"working_tree": False}, {"index": False, "untracked_files": True}, {"path": "ignored"}]
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        untracked = repo.untracked_files
        ignored = repo.ignored(*paths)
        dirty = [repo.is_dirty(**option) for option in options]
    assert Path(repo.index.path).read_bytes() == index_before
    with patch.object(_backend, "gix", None):
        assert untracked == repo.untracked_files
        assert ignored == repo.ignored(*paths)
        assert dirty == [repo.is_dirty(**option) for option in options]


def test_native_status_tracks_submodule_dirtiness(repo):
    root = Path(repo.working_dir)
    with Repo.init(root.parent / "source", object_format=repo.git.rev_parse("--show-object-format")) as source:
        Path(source.working_dir, "file").write_text("initial")
        source.index.add(["file"])
        source.index.commit("initial", skip_hooks=True)
        module = repo.create_submodule("module", "module", source.working_dir)
    repo.index.commit("add submodule", skip_hooks=True)
    with module.module() as child:
        Path(child.working_dir, "file").write_text("modified")
    options = [{}, {"submodules": False}, {"working_tree": False}, {"index": False}]
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        dirty = [repo.is_dirty(**option) for option in options]
    assert dirty == [True, False, False, True]
    with patch.object(_backend, "gix", None):
        assert dirty == [repo.is_dirty(**option) for option in options]


def test_native_commit_statistics_match_cli(repo):
    root = Path(repo.working_dir)
    for name, content in (("file", b"one\ntwo\n"), ("binary", b"a\0b"), ("old", b"gone\n"), ("link", b"text")):
        (root / name).write_bytes(content)
    repo.index.add(["file", "binary", "old", "link"])
    first = repo.index.commit("first", skip_hooks=True)
    (root / "file").write_bytes(b"two\nthree\nfour\n")
    (root / "binary").write_bytes(b"b\0c")
    (root / "old").rename(root / "new")
    (root / "link").unlink()
    (root / "link").symlink_to("file")
    repo.git.add("--all")
    second = repo.index.commit("second", skip_hooks=True)
    empty = repo.index.commit("empty", skip_hooks=True)
    with patch.object(Git, "execute", side_effect=AssertionError("unexpected CLI call")):
        native = [(commit.stats.total, commit.stats.files) for commit in (first, second, empty)]
    with patch.object(_backend, "gix", None):
        assert native == [(commit.stats.total, commit.stats.files) for commit in (first, second, empty)]
    # Git consults uncommitted attributes too; native tree caches currently do not.
    (root / ".gitattributes").write_text("file -diff\n")
    stats = second.stats
    with patch.object(_backend, "gix", None):
        assert (stats.total, stats.files) == (second.stats.total, second.stats.files)
