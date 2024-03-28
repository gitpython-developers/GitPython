# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests of assorted deprecation warnings with no extra subtleties to check."""

import gc
import warnings

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
    """The deprecated Diff.renamed property issues a deprecation warning."""
    with pytest.deprecated_call():
        single_diff.renamed


def test_diff_renamed_file_does_not_warn(single_diff):
    """The preferred Diff.renamed_file property issues no deprecation warning."""
    with warnings.catch_warnings():
        # FIXME: Refine this to filter for deprecation warnings from GitPython.
        warnings.simplefilter("error", DeprecationWarning)
        single_diff.renamed_file
