"""Repository-format independent object/index operations and their safety boundary."""

import os
from io import BytesIO
from pathlib import Path

import pytest
from gitdb.base import IStream

from git import Actor, Commit, IndexFile, Repo, Tree
from git.exc import GitCommandError, HookExecutionError, UnmergedEntriesError, UnsafeOptionError
from git.index.typ import BaseIndexEntry, IndexEntry


@pytest.fixture(params=[(h, r) for h in ("sha1", "sha256") for r in ("files", "reftable")])
def repo(request, tmp_path):
    with Repo.init(tmp_path, object_format=request.param[0], ref_format=request.param[1]) as repository:
        yield repository


def test_objects_index_commit_and_merge(repo):
    root = Path(repo.working_tree_dir)
    names = ["space name", "--option", "unicode-é", "dir/file"]
    if os.name != "nt":
        names.extend(["line\nname", "tab\tname"])
    for name in names:
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(name)
    index = repo.index
    index.add(names, write=False)
    assert not Path(index.path).exists()
    tree = index.write_tree()
    assert not Path(index.path).exists()
    assert {blob.path for blob in tree.traverse() if blob.type == "blob"} == set(names)
    assert len(tree.binsha) == repo._oid_size
    index.write()
    assert {(e.path, e.stage) for e in repo.index.iter_entries()} == {(name, 0) for name in names}
    actor = Actor("Example", "example@example.com")
    commit = index.commit("message without newline", author=actor, committer=actor, skip_hooks=True)
    assert repo.commit(commit.hexsha).message == "message without newline"
    assert repo.head.commit == commit
    assert commit.replace().hexsha == commit.hexsha
    updated = commit.replace(message="updated")
    assert repo.commit(updated.hexsha).message == "updated"
    assert repo.head.commit == commit
    checkout_name = "--option" if os.name == "nt" else "line\nname"
    (root / checkout_name).write_text("modified")
    index.checkout([checkout_name], force=True)
    assert (root / checkout_name).read_text() == checkout_name
    before = Path(index.path).read_bytes()
    virtual = IndexFile.from_tree(repo, tree)
    assert virtual.write_tree() == tree
    assert Path(index.path).read_bytes() == before
    assert IndexFile.new(repo, tree.binsha, tree.hexsha).write_tree() == tree
    merge_base = repo.merge_base(commit, commit)
    assert IndexFile.from_tree(repo, merge_base).write_tree() == tree
    index.merge_tree(commit, base=merge_base)
    assert index.write_tree() == tree


def test_tree_names_do_not_require_worktree_support(repo):
    tree = Tree(repo, repo._null_binsha, path="")
    tree._cache = [
        (b"a" * repo._oid_size, 0o100644, name) for name in ("line\nname", "tab\tname", "name:with:colons", "\udc9f")
    ]
    data = BytesIO()
    tree._serialize(data)
    data.seek(0)
    stored = repo.odb.store(IStream("tree", len(data.getvalue()), data))
    assert Tree(repo, stored.binsha, path="")._cache == sorted(tree._cache, key=lambda entry: entry[2])


def test_index_stages_missing_objects_and_atomic_failure(repo):
    index = repo.index
    missing = b"a" * repo._oid_size
    for stage in (1, 2, 3):
        entry = BaseIndexEntry((0o100644, missing, stage << 12, "conflict"))
        index.add([IndexEntry.from_base(entry)], write=False)
    index.write()
    assert {stage for path, stage in [(e.path, e.stage) for e in repo.index.iter_entries()]} == {1, 2, 3}
    before = Path(index.path).read_bytes()
    with pytest.raises(UnmergedEntriesError):
        index.write_tree()
    index.remove(".", r=True, force=True, write=False)
    index.add([IndexEntry((0o100644, missing, 0, "missing"))], write=False)
    tree = index.write_tree()
    assert tree["missing"].binsha == missing
    assert Path(index.path).read_bytes() == before
    with pytest.raises(ValueError):
        index.add([IndexEntry((0o100644, missing, 0, "../escape"))])
    assert Path(index.path).read_bytes() == before
    assert not Path(str(index.path) + ".lock").exists()


def test_index_flags_are_preserved_until_path_is_staged(repo):
    root = Path(repo.working_tree_dir)
    (root / "intent").touch()
    (root / "skip").write_text("skip")
    repo.git.add("-N", "--", "intent")
    repo.git.add("--", "skip")
    repo.git.update_index("--skip-worktree", "--", "skip")
    before = repo.git.status(porcelain=True)
    index = repo.index
    assert index.entry(*("skip", 0)).skip_worktree
    index.write()
    assert repo.git.status(porcelain=True) == before
    index.add(["intent"])
    assert "A  intent" in repo.git.status(porcelain=True)
    assert repo.index.entry(*("skip", 0)).skip_worktree


def test_revision_injection_cannot_write_or_checkout(repo, tmp_path):
    index = repo.index
    for operand in ("--index-output=" + str(tmp_path / "victim"), "--reset", "HEAD\nHEAD", "HEAD\0HEAD"):
        for revision in (operand, [operand]):
            with pytest.raises((UnsafeOptionError, ValueError)):
                IndexFile.from_tree(repo, revision)
    for revisions in ([], ["HEAD", "HEAD"]):
        with pytest.raises(ValueError):
            IndexFile.from_tree(repo, revisions)
    assert not (tmp_path / "victim").exists()
    assert not Path(index.path).exists()


def test_commit_hooks_use_git_and_keep_their_index_changes(repo):
    root = Path(repo.working_tree_dir)
    (root / "file").write_text("before")
    index = repo.index
    index.add(["file"])
    hooks = Path(repo.git_dir) / "hooks"
    hooks.mkdir(exist_ok=True)
    pre = hooks / "pre-commit"
    pre.write_text("#!/bin/sh\nprintf after >file\ngit add -- file\n")
    pre.chmod(0o755)
    msg = hooks / "commit-msg"
    msg.write_text('#!/bin/sh\nprintf " hook" >>"$1"\n')
    msg.chmod(0o755)
    commit = index.commit("message")
    assert commit.message == "message hook"
    assert commit.tree["file"].data_stream.read() == b"after"
    assert repo.index.write_tree() == commit.tree
    pre.write_text("#!/bin/sh\nexit 7\n")
    with pytest.raises(HookExecutionError) as failure:
        index.commit("rejected")
    assert failure.value.status == 7
    assert repo.head.commit == commit


def test_bare_index_and_virtual_commit(tmp_path):
    with Repo.init(tmp_path, bare=True, object_format="sha256", ref_format="reftable") as repo:
        index = repo.index
        tree = index.write_tree()
        commit = Commit.create_from_tree(repo, tree, "", parent_commits=[], head=True)
        assert repo.head.commit == commit
        virtual = IndexFile.from_tree(repo, tree)
        next_commit = virtual.commit("virtual", head=False)
        assert next_commit.parents == [commit] or tuple(next_commit.parents) == (commit,)
        assert repo.head.commit == commit


@pytest.mark.parametrize("storage", ["v4", "split", "sparse"])
def test_git_index_storage_variants(repo, storage):
    root = Path(repo.working_tree_dir)
    for name in ("inside/file", "outside/file"):
        path = root / name
        path.parent.mkdir()
        path.write_text(name)
    repo.index.add(["inside", "outside"])
    commit = repo.index.commit("initial", skip_hooks=True)
    if storage == "v4":
        repo.git.update_index("--index-version=4")
    elif storage == "split":
        repo.git.update_index("--split-index")
    else:
        repo.git.sparse_checkout("init", "--cone", "--sparse-index")
        repo.git.sparse_checkout("set", "inside")
    index = repo.index
    assert {(e.path, e.stage) for e in index.iter_entries()} == {("inside/file", 0), ("outside/file", 0)}
    assert index.write_tree() == commit.tree
    (root / "inside/file").write_text("changed")
    index.add(["inside/file"])
    assert index.write_tree()["inside/file"].data_stream.read() == b"changed"
    if storage == "v4":
        assert index.version == 4
    elif storage == "split":
        assert repo.git.rev_parse("--shared-index-path")


def test_trailer_commands_are_not_executed(repo):
    marker = Path(repo.working_tree_dir) / "executed"
    with repo.config_writer() as config:
        config.set_value('trailer "custom"', "cmd", "touch " + str(marker))
    with pytest.raises(UnsafeOptionError):
        Commit.create_from_tree(repo, repo.index.write_tree(), "message", trailers={"custom": "value"})
    assert not marker.exists()


def test_pending_index_queries_removal_and_failed_update(repo):
    root = Path(repo.working_tree_dir)
    (root / "file").write_text("old")
    index = repo.index
    index.add(["file"])
    published = Path(index.path).read_bytes()
    original = index.entry("file")
    (root / "file").write_text("new")
    index.add(["file"], write=False)
    pending = index.entry("file")
    assert pending.binsha != original.binsha
    assert not hasattr(index, "entries")
    with pytest.raises(ValueError, match="Git did not retain"):
        index.add([BaseIndexEntry((0o120000, pending.binsha, 0, ".gitmodules"))], write=False)
    with pytest.raises(ValueError, match="Invalid index path"):
        index.reset(index.write_tree().hexsha, paths=["file\0injected"])
    assert index.entry("file") == pending
    assert Path(index.path).read_bytes() == published
    (root / "file").unlink()
    assert list(index.checkout(["file"])) == ["file"]
    assert (root / "file").read_text() == "new"
    assert Path(index.path).read_bytes() == published
    with pytest.raises(ValueError):
        index.remove(["file"], working_tree=True, write=False)
    index.remove(["file"], force=True, write=False)
    with pytest.raises(KeyError):
        index.entry("file")
    assert Path(index.path).read_bytes() == published
    index.write()
    assert list(repo.index.iter_entries()) == []


def test_malformed_index_failure_is_propagated(repo):
    Path(repo.index.path).write_bytes(b"not an index")
    with pytest.raises((ValueError, GitCommandError)):
        list(repo.index.iter_entries())


def test_failed_hook_retains_index_edit_without_advancing_head(repo):
    if os.name == "nt":
        pytest.skip("POSIX shell hook")
    root = Path(repo.working_tree_dir)
    (root / "file").write_text("old")
    index = repo.index
    index.add(["file"])
    initial = index.commit("initial", skip_hooks=True)
    virtual = IndexFile.from_tree(repo, initial.tree)
    hook = Path(repo.git_dir, "hooks", "pre-commit")
    hook.write_text("#!/bin/sh\nprintf changed > file\ngit add file\nexit 1\n")
    hook.chmod(0o755)
    with pytest.raises(HookExecutionError):
        virtual.commit("must fail")
    assert repo.head.commit == initial
    assert virtual.entry("file").to_blob(repo).data_stream.read() == b"changed"
    assert repo.index.entry("file").to_blob(repo).data_stream.read() == b"old"


def test_commit_and_tag_metadata_preserves_encoding_signature_and_message(repo):
    tree = repo.index.write_tree()
    identity = b"M\xe9 <name@example.invalid> 1112911991 -0200"
    message = "\nexact café\n\n".encode("latin1")
    raw = (
        b"tree "
        + tree.hexsha.encode()
        + b"\nauthor "
        + identity
        + b"\ncommitter "
        + identity
        + b"\nencoding ISO-8859-1\nmergetag object "
        + tree.hexsha.encode()
        + b"\n type tree\n tag merged\ngpgsig fake signature\n continuation\n\n"
        + message
    )
    stored = repo.odb.store(IStream("commit", len(raw), BytesIO(raw)))
    commit = Commit(repo, stored.binsha)
    assert commit.author == Actor("Mé", "name@example.invalid")
    assert commit.authored_date == 1112911991
    assert commit.author_tz_offset == 7200
    assert commit.encoding == "ISO-8859-1"
    assert commit.gpgsig == "fake signature\ncontinuation"
    assert commit.message == "\nexact café\n\n"
    tag_raw = (
        b"object " + commit.hexsha.encode() + b"\ntype commit\ntag arbitrary\n"
        b"tagger Tagger <tag@example.invalid> 1112911991 +0200\n\n\nmessage\n\n"
    )
    stored = repo.odb.store(IStream("tag", len(tag_raw), BytesIO(tag_raw)))
    from git import TagObject

    tag = TagObject(repo, stored.binsha)
    assert tag.object == commit
    assert tag.tag == "arbitrary"
    assert tag.tagger == Actor("Tagger", "tag@example.invalid")
    assert tag.tagged_date == 1112911991
    assert tag.tagger_tz_offset == -7200
    assert tag.message == "\nmessage\n"
