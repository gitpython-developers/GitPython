# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests of assorted deprecation warnings with no extra subtleties to check."""

import contextlib
import gc
import warnings

import pytest

from git.diff import NULL_TREE
from git.repo import Repo


@contextlib.contextmanager
def _assert_no_deprecation_warning():
    """Context manager to assert that code does not issue any deprecation warnings."""
    with warnings.catch_warnings():
        # FIXME: Refine this to filter for deprecation warnings from GitPython.
        warnings.simplefilter("error", DeprecationWarning)
        yield


@pytest.fixture
def commit(tmp_path):
    """Fixture to supply a one-commit repo's commit, enough for deprecation tests."""
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8")
    repo = Repo.init(tmp_path)
    repo.index.add(["a.txt"])
    yield repo.index.commit("Initial commit")
    del repo
    gc.collect()


@pytest.fixture
def diff(commit):
    """Fixture to supply a single-file diff."""
    (diff,) = commit.diff(NULL_TREE)  # Exactly one file in the diff.
    yield diff


def test_diff_renamed_warns(diff):
    """The deprecated Diff.renamed property issues a deprecation warning."""
    with pytest.deprecated_call():
        diff.renamed


def test_diff_renamed_file_does_not_warn(diff):
    """The preferred Diff.renamed_file property issues no deprecation warning."""
    with _assert_no_deprecation_warning():
        diff.renamed_file
