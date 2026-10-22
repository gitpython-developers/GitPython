"""Public GitPython queries used by released downstream projects."""

from pathlib import Path
from importlib.metadata import version

import pytest

import git
import git.db

from test.lib.fixtures import fixture_repo, read_only_fixture


def test_public_version_supports_downstream_provider_checks():
    assert git.__version__ == version("GitPython")


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_repo_accepts_explicit_literal_path_selection(object_format, ref_format, monkeypatch):
    root = read_only_fixture("downstream-literal-repo.sh", object_format, ref_format)
    monkeypatch.setenv("DOWNSTREAM_REPOSITORY", str(root / "expanded"))
    literal = root / "$DOWNSTREAM_REPOSITORY"
    for kwargs in ({}, {"expand_vars": False}):
        with git.Repo(literal, **kwargs) as repo:
            assert repo.head.commit.tree["tracked"].data_stream.read() == b"$DOWNSTREAM_REPOSITORY"
    with git.Repo(literal, git.GitCmdObjectDB, False, False) as repo:
        assert Path(repo.working_tree_dir) == literal
    with pytest.raises(ValueError, match="Environment variable expansion is unsupported"):
        git.Repo(literal, expand_vars=True)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_revision_root_tree_retains_iterable_path_context(object_format, ref_format):
    with fixture_repo("downstream-revision-path.sh", object_format, ref_format) as repo:
        for revision in ("HEAD:", "HEAD^{}:", "HEAD^{/initial: with colon}:"):
            tree = repo.rev_parse(revision)
            assert tree.path == ""
            assert tree.mode == 0o40000
            assert [entry.path for entry in tree] == ["dir", "tracked"]
            assert tree["dir/file"].data_stream.read() == b"nested"


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_missing_revision_paths_retain_tree_lookup_errors(object_format, ref_format):
    with fixture_repo("downstream-revision-path.sh", object_format, ref_format) as repo:
        for revision, missing in (
            ("HEAD:nope", "nope"),
            ("HEAD:dir/nope", "nope"),
            ("HEAD:nope/child", "nope"),
            ("HEAD:tracked/child", "tracked/child"),
            ("HEAD^{}:nope", "nope"),
            ("HEAD^{/initial: with colon}:nope", "nope"),
        ):
            with pytest.raises(KeyError) as error:
                repo.rev_parse(revision)
            assert error.value.args == ("Blob or Tree named %r not found" % missing,)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_local_tracking_branch_uses_gits_upstream_location(object_format, ref_format):
    with fixture_repo("downstream-local-upstream.sh", object_format, ref_format) as repo:
        upstream = repo.head.reference.tracking_branch()
        assert isinstance(upstream, git.Head)
        assert upstream.path == repo.git.rev_parse("--symbolic-full-name", "@{upstream}")
        assert upstream.name == "upstream"
        assert not upstream.is_remote()
        assert upstream.commit == repo.head.commit


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_legacy_gitdb_selector_uses_the_managed_object_backend(object_format, ref_format):
    assert git.GitDB is git.db.GitDB is git.GitCmdObjectDB
    with fixture_repo("downstream-index.sh", object_format, ref_format) as fixture:
        with git.Repo(fixture.working_tree_dir, odbt=git.GitDB) as repo:
            assert isinstance(repo.odb, git.GitCmdObjectDB)
            blob = repo.head.commit.tree["tracked"]
            assert repo.odb.has_object(blob.binsha)
            info = repo.odb.info(blob.binsha)
            assert info.binsha == blob.binsha
            assert info.type == b"blob"
            assert repo.odb.stream(blob.binsha).read() == blob.data_stream.read()


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_index_entries_readers_retain_pending_and_published_snapshots(object_format, ref_format):
    with fixture_repo("downstream-index.sh", object_format, ref_format, write=True) as repo:
        index = repo.index
        published_bytes = Path(index.path).read_bytes()
        entries = index.entries
        assert len(entries) == 4
        assert set(entries.keys()) == {("tracked", 0), *(("conflict", stage) for stage in (1, 2, 3))}
        assert [str(key[0]) for key in entries].count("conflict") == 3
        assert entries[("tracked", 0)].binsha == repo.head.commit.tree["tracked"].binsha
        assert all(entry.path == path and entry.stage == stage for (path, stage), entry in entries.items())
        with pytest.raises(KeyError):
            entries[("missing", 0)]
        with pytest.raises(TypeError):
            entries[("tracked", 0)] = entries[("conflict", 1)]
        index.add(["tracked"], write=False)
        pending = index.entries
        assert pending[("tracked", 0)].binsha != entries[("tracked", 0)].binsha
        assert repo.index.entries[("tracked", 0)] == entries[("tracked", 0)]
        assert Path(index.path).read_bytes() == published_bytes
        index.write()
        assert repo.index.entries == pending
        assert entries[("tracked", 0)].binsha == repo.head.commit.tree["tracked"].binsha


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_git_directory_option_selects_the_requested_worktree(object_format, ref_format):
    # Linked-worktree registration contains absolute paths that cannot be copied.
    with fixture_repo("downstream-worktree.sh", object_format, ref_format, write=True, execute=True) as repo:
        root = Path(repo.working_tree_dir).parent
        linked = root / "linked"
        original_index = Path(repo.index.path).read_bytes()
        assert not (linked / "tracked").exists()
        process = repo.git(C=str(linked)).checkout("--force", as_process=True)
        process.wait()
        assert (linked / "tracked").read_text() == "original"
        assert Path(repo.working_tree_dir, "tracked").read_text() == "unchanged"
        assert Path(repo.index.path).read_bytes() == original_index
        assert Path(repo.git(C=str(linked)).rev_parse("--show-toplevel")).samefile(linked)
        assert repo.git(C=str(root / "other")).show("HEAD:tracked") == "other"
        repo.git.set_persistent_git_options(C=str(linked))
        assert Path(repo.git.rev_parse("--show-toplevel")).samefile(linked)
        repo.git.set_persistent_git_options()
        assert Path(repo.git.rev_parse("--show-toplevel")).samefile(repo.working_tree_dir)


def test_git_directory_option_retains_explicit_environment():
    # Linked-worktree registration contains absolute paths that cannot be copied.
    with fixture_repo("downstream-worktree.sh", "sha1", "files", write=True, execute=True) as repo:
        root = Path(repo.working_tree_dir).parent
        other = root / "other"
        with repo.git.custom_environment(GIT_DIR=repo.git_dir, GIT_WORK_TREE=repo.working_tree_dir):
            assert repo.git(C=str(other)).show("HEAD:tracked") == "original"
        assert repo.git(C=str(other)).show("HEAD:tracked") == "other"
        assert repo.git(C=str(other)).show("HEAD:tracked", env={"GIT_DIR": repo.git_dir}) == "original"


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_separate_git_directory_retains_the_supplied_checkout(object_format, ref_format):
    with fixture_repo("downstream-separate-git-dir.sh", object_format, ref_format, write=True) as repo:
        assert Path(repo.working_tree_dir).name == "repo"
        assert Path(repo.git_dir).name == "metadata"
        assert Path(repo.git.rev_parse("--show-toplevel")).samefile(repo.working_tree_dir)
        assert repo.index.entry("tracked").to_blob(repo).data_stream.read() == b"tracked"
        Path(repo.working_tree_dir, "tracked").write_text("updated")
        repo.index.add(["tracked"])
        assert repo.index.commit("updated").tree["tracked"].data_stream.read() == b"updated"
