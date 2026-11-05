# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Verify that generated fixtures are isolated, reusable, and usable by Git."""

import os
import subprocess
import shutil
import sys
from pathlib import Path

import pytest
from gix import Error, testtools

from test.lib.fixtures import fixture_repo, read_only_fixture, writable_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_shared_fixture_works_without_checkout_history(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    shutil.copytree(REPO_ROOT / "test/lib", source / "test/lib", ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("__init__.py", "cleanup.py"):
        shutil.copyfile(REPO_ROOT / "test" / name, source / "test" / name)
    shutil.copytree(
        REPO_ROOT / "tests/fixtures",
        source / "tests/fixtures",
        ignore=shutil.ignore_patterns("generated-*", "__pycache__"),
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from test.lib import TestBase; "
            "TestBase.setUpClass(); "
            "assert TestBase.rorepo.head.commit.parents; "
            "TestBase.tearDownClass()",
        ],
        cwd=source,
        env={
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "GIT_PYTHON_BACKEND"}
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_scripted_readonly_fixture_reuses_initial_state():
    path = read_only_fixture("fixture-lifecycle.sh")
    assert read_only_fixture("fixture-lifecycle.sh") == path
    with fixture_repo("fixture-lifecycle.sh") as repo:
        assert repo.head.commit.tree["file"].data_stream.read() == b"initial"
        assert Path(repo.working_tree_dir, "file").read_text() == "initial"


def test_scripted_writable_fixture_copies_and_closes_repository():
    baseline = read_only_fixture("fixture-lifecycle.sh")
    with fixture_repo("fixture-lifecycle.sh", write=True) as repo:
        root = Path(repo.working_tree_dir)
        assert not (root / "file").samefile(baseline / "repo/file")
        (root / "file").write_text("private")
        repo.index.add(["file"])
        repo.index.commit("Private change", skip_hooks=True)
    assert not root.exists()
    assert (baseline / "repo/file").read_text() == "initial"


def test_scripted_execute_fixture_uses_its_final_location():
    # The recorded absolute path cannot be relocated by copying the cached fixture.
    with writable_fixture("fixture-lifecycle.sh", execute=True) as temporary:
        root = temporary.path().resolve()
        assert Path((root / "location").read_text().strip()).samefile(root / "repo")


def test_fixture_cache_keeps_arguments_before_absolute_paths_distinct():
    first = read_only_fixture("fixture-lifecycle.sh", "first", REPO_ROOT)
    second = read_only_fixture("fixture-lifecycle.sh", "second", REPO_ROOT)
    assert first != second
    assert (first / "scenario").read_text().strip() == "first"
    assert (second / "scenario").read_text().strip() == "second"


def test_script_failure_does_not_report_inherited_environment(monkeypatch):
    def fail(*args):
        raise Error("fixture command failed: PRIVATE_TOKEN=do-not-report")

    monkeypatch.setattr(testtools, "scripted_fixture_read_only_with_args_with_post", fail)
    with pytest.raises(RuntimeError) as caught:
        read_only_fixture("fixture-lifecycle.sh")
    assert "fixture-lifecycle.sh" in str(caught.value)
    assert "PRIVATE_TOKEN" not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("name", ["repo", "gitdb", "smmap"])
def test_generated_repository_is_self_contained_and_trusted(name):
    path = read_only_fixture("sample-repositories.sh") / name
    assert not (path / ".git/objects/info/alternates").exists()
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=path, capture_output=True, text=True, check=True
    )
    assert Path(result.stdout.strip()).samefile(path)
