# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests of assorted deprecation warnings when there are no extra subtleties to check.

This tests deprecation warnings where all that needs be verified is that a deprecated
property, function, or class issues a DeprecationWarning when used and, if applicable,
that recommended alternatives do not issue the warning.

This is in contrast to other modules within test.deprecation, which test warnings where
there is a risk of breaking other runtime behavior, or of breaking static type checking
or making it less useful, by introducing the warning or in plausible future changes to
how the warning is implemented. That happens when it is necessary to customize attribute
access on a module or class, in a way it was not customized before, to issue a warning.
It is inapplicable to the deprecations whose warnings are tested in this module.
"""

import pytest

from git.diff import NULL_TREE
from git.objects.util import Traversable
from git.repo import Repo
from git.util import Iterable as _Iterable, IterableObj

from .lib import assert_no_deprecation_warning

# typing -----------------------------------------------------------------

from typing import Generator, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from git.diff import Diff, DiffIndex
    from git.objects.commit import Commit

# ------------------------------------------------------------------------


@pytest.fixture
def commit(tmp_path: "Path") -> Generator["Commit", None, None]:
    """Fixture to supply a one-commit repo's commit, enough for deprecation tests."""
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8")
    repo = Repo.init(tmp_path)
    repo.index.add(["a.txt"])
    yield repo.index.commit("Initial commit")
    repo.close()


@pytest.fixture
def diff(commit: "Commit") -> Generator["Diff", None, None]:
    """Fixture to supply a single-file diff."""
    (diff,) = commit.diff(NULL_TREE)  # Exactly one file in the diff.
    yield diff


@pytest.fixture
def diffs(commit: "Commit") -> Generator["DiffIndex", None, None]:
    """Fixture to supply a DiffIndex."""
    yield commit.diff(NULL_TREE)


def test_diff_renamed_warns(diff: "Diff") -> None:
    """The deprecated Diff.renamed property issues a deprecation warning."""
    with pytest.deprecated_call():
        diff.renamed


def test_diff_renamed_file_does_not_warn(diff: "Diff") -> None:
    """The preferred Diff.renamed_file property issues no deprecation warning."""
    with assert_no_deprecation_warning():
        diff.renamed_file


def test_commit_trailers_warns(commit: "Commit") -> None:
    """The deprecated Commit.trailers property issues a deprecation warning."""
    with pytest.deprecated_call():
        commit.trailers


def test_commit_trailers_list_does_not_warn(commit: "Commit") -> None:
    """The nondeprecated Commit.trailers_list property issues no deprecation warning."""
    with assert_no_deprecation_warning():
        commit.trailers_list


def test_commit_trailers_dict_does_not_warn(commit: "Commit") -> None:
    """The nondeprecated Commit.trailers_dict property issues no deprecation warning."""
    with assert_no_deprecation_warning():
        commit.trailers_dict


def test_traverse_list_traverse_in_base_class_warns(commit: "Commit") -> None:
    """Traversable.list_traverse's base implementation issues a deprecation warning."""
    with pytest.deprecated_call():
        Traversable.list_traverse(commit)


def test_traversable_list_traverse_override_does_not_warn(commit: "Commit") -> None:
    """Calling list_traverse on concrete subclasses is not deprecated, does not warn."""
    with assert_no_deprecation_warning():
        commit.list_traverse()


def test_traverse_traverse_in_base_class_warns(commit: "Commit") -> None:
    """Traversable.traverse's base implementation issues a deprecation warning."""
    with pytest.deprecated_call():
        Traversable.traverse(commit)


def test_traverse_traverse_override_does_not_warn(commit: "Commit") -> None:
    """Calling traverse on concrete subclasses is not deprecated, does not warn."""
    with assert_no_deprecation_warning():
        commit.traverse()


def test_iterable_inheriting_warns() -> None:
    """Subclassing the deprecated git.util.Iterable issues a deprecation warning."""
    with pytest.deprecated_call():

        class Derived(_Iterable):
            pass


def test_iterable_obj_inheriting_does_not_warn() -> None:
    """Subclassing git.util.IterableObj is not deprecated, does not warn."""
    with assert_no_deprecation_warning():

        class Derived(IterableObj):
            pass


def test_diff_iter_change_type(diffs: "DiffIndex") -> None:
    """The internal DiffIndex.iter_change_type function issues no deprecation warning."""
    with assert_no_deprecation_warning():
        for change_type in diffs.change_type:
            [*diffs.iter_change_type(change_type=change_type)]
