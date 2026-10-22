"""Public GitPython queries used by released downstream projects."""

from pathlib import Path

import pytest

from test.lib.fixtures import fixture_repo


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
    with fixture_repo("downstream-worktree.sh", object_format, ref_format, write=True) as repo:
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
    with fixture_repo("downstream-worktree.sh", "sha1", "files", write=True) as repo:
        root = Path(repo.working_tree_dir).parent
        other = root / "other"
        with repo.git.custom_environment(GIT_DIR=repo.git_dir, GIT_WORK_TREE=repo.working_tree_dir):
            assert repo.git(C=str(other)).show("HEAD:tracked") == "original"
        assert repo.git(C=str(other)).show("HEAD:tracked") == "other"
        assert repo.git(C=str(other)).show("HEAD:tracked", env={"GIT_DIR": repo.git_dir}) == "original"
