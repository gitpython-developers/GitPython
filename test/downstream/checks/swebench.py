"""Supplemental checks: SWE-bench 5.0.2 ships no tests for its GitPython callers.

Import the ordinary upstream utility module. The minimal environment only needs
chardet, GitPython and GixPython fixtures; no SWE-bench code or imported module is replaced.
"""

import logging
from pathlib import Path

import pytest
from gix import Error, testtools
from git import Repo
from swebench.inference.make_datasets.utils import (
    AutoContextManager,
    ingest_directory_contents,
)


@pytest.fixture
def checkout_fixture(object_format, ref_format):
    script = Path(__file__).resolve().parents[3] / "tests/fixtures/downstream-swebench.sh"
    # The URL rewrite embeds the private fixture's absolute origin path.
    try:
        fixture = testtools.scripted_fixture_writable_with_args(
            script, [object_format, ref_format], testtools.Creation.Execute
        )
    except Error:
        raise RuntimeError("SWE-bench fixture script failed; see its captured output") from None
    try:
        yield fixture.path().resolve()
    finally:
        try:
            fixture.close()
        except Error:
            logging.getLogger(__name__).warning("Could not completely clean up SWE-bench fixture")


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_auto_context_manager_clones_and_resets(checkout_fixture, monkeypatch, object_format, ref_format):
    """Clone, revisit commits and reuse the checkout with real GitPython."""
    tmp_path = checkout_fixture
    origin = tmp_path / "origin"
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_DEFAULT_REF_FORMAT", ref_format)
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
    first_commit = (tmp_path / "first-commit").read_text().strip()
    second_commit = (tmp_path / "second-commit").read_text().strip()
    root = tmp_path / "checkouts"
    instance = {"repo": "fixture/project", "base_commit": first_commit}
    original_cwd = Path.cwd()
    manager = AutoContextManager(instance, root_dir=str(root), token="gitpython-tests")
    checkout = Path(manager.repo_path)
    with manager as context:
        assert Path.cwd() == checkout
        assert context.get_readme_files() == ["README.md"]
        assert ingest_directory_contents(checkout, include_tests=True) == {"module.py": "value = 1\n"}
        with Repo(checkout) as repo:
            assert repo.head.commit.hexsha == first_commit
            assert repo.git.rev_parse("--show-object-format") == object_format
            assert repo.git.rev_parse("--show-ref-format") == ref_format
    assert Path.cwd() == original_cwd

    # Reuse the local clone even when its source no longer exists. Reset must
    # remove both modified tracked contents and untracked files from a prior run.
    origin.rename(tmp_path / "unavailable-origin")
    (checkout / "module.py").write_text("dirty = True\n")
    (checkout / "untracked.py").write_text("untracked = True\n")
    instance["base_commit"] = second_commit
    with AutoContextManager(instance, root_dir=str(root), token="gitpython-tests") as context:
        assert Path(context.repo_path) == checkout
        assert ingest_directory_contents(checkout, include_tests=True) == {"module.py": "value = 2\n"}
    assert Path.cwd() == original_cwd
