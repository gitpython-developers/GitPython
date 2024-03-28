# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests of assorted deprecation warnings with no extra subtleties to check."""

import gc

import pytest

from git.diff import NULL_TREE
from git.repo import Repo


@pytest.fixture
def single_diff(tmp_path):
    """Fixture to supply a single-file diff."""
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8")
    repo = Repo.init(tmp_path)
    repo.index.add(["a.txt"])
    commit = repo.index.commit("Initial commit")
    (diff,) = commit.diff(NULL_TREE)  # Exactly one file in the diff.
    yield diff
    del repo, commit, diff
    gc.collect()


def test_diff_renamed_warns(single_diff):
    with pytest.deprecated_call():
        single_diff.renamed
