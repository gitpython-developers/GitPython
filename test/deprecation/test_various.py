# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests of assorted deprecation warnings with no extra subtleties to check."""

from git.diff import NULL_TREE
from git.repo import Repo

import pytest


def test_diff_renamed_warns(tmp_path):
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8")
    repo = Repo.init(tmp_path)
    repo.index.add(["a.txt"])
    commit = repo.index.commit("Initial commit")
    (diff,) = commit.diff(NULL_TREE)  # Exactly one file in the diff.

    with pytest.deprecated_call():
        diff.renamed
