# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests for dynamic and static characteristics of top-level git module attributes.

Provided mypy has ``warn_unused_ignores = true`` set, running mypy on these test cases
checks static typing of the code under test. This is the reason for the many separate
single-line attr-defined suppressions, so those should not be replaced with a smaller
number of more broadly scoped suppressions, even where it is feasible to do so.

Running pytest checks dynamic behavior as usual.
"""

import itertools
import sys
from typing import Type

if sys.version_info >= (3, 11):
    from typing import assert_type
else:
    from typing_extensions import assert_type

import pytest

import git
import git.index.base
import git.index.fun
import git.index.typ
import git.refs.head
import git.refs.log
import git.refs.reference
import git.refs.symbolic
import git.refs.tag


def test_cannot_access_undefined() -> None:
    """Accessing a bogus attribute in git remains a dynamic and static error."""
    with pytest.raises(AttributeError):
        git.foo  # type: ignore[attr-defined]


def test_cannot_import_undefined() -> None:
    """Importing a bogus attribute from git remains a dynamic and static error."""
    with pytest.raises(ImportError):
        from git import foo  # type: ignore[attr-defined]  # noqa: F401


def test_util_alias_access() -> None:
    """Accessing util in git works, warns, and mypy verifies it and its attributes."""
    # The attribute access should succeed.
    with pytest.deprecated_call() as ctx:
        util = git.util

    # There should be exactly one warning and it should have our util-specific message.
    (message,) = [str(entry.message) for entry in ctx]
    assert "git.util" in message
    assert "git.index.util" in message
    assert "should not be relied on" in message

    # We check access through the util alias to the TemporaryFileSwap member, since it
    # is slightly simpler to validate and reason about than the other public members,
    # which are functions (specifically, higher-order functions for use as decorators).
    from git.index.util import TemporaryFileSwap

    assert_type(util.TemporaryFileSwap, Type[TemporaryFileSwap])

    # This comes after the static assertion, just in case it would affect the inference.
    assert util.TemporaryFileSwap is TemporaryFileSwap


def test_util_alias_import() -> None:
    """Importing util from git works, warns, and mypy verifies it and its attributes."""
    # The import should succeed.
    with pytest.deprecated_call() as ctx:
        from git import util

    # There may be multiple warnings. In CPython there will be currently always be
    # exactly two, possibly due to the equivalent of calling hasattr to do a pre-check
    # prior to retrieving the attribute for actual use. However, all warnings should
    # have the same message, and it should be our util-specific message.
    (message,) = {str(entry.message) for entry in ctx}
    assert "git.util" in message, "Has alias."
    assert "git.index.util" in message, "Has target."
    assert "should not be relied on" in message, "Distinct from other messages."

    # As above, we check access through the util alias to the TemporaryFileSwap member.
    from git.index.util import TemporaryFileSwap

    assert_type(util.TemporaryFileSwap, Type[TemporaryFileSwap])

    # This comes after the static assertion, just in case it would affect the inference.
    assert util.TemporaryFileSwap is TemporaryFileSwap


_PRIVATE_MODULE_ALIAS_TARGETS = (
    git.refs.head,
    git.refs.log,
    git.refs.reference,
    git.refs.symbolic,
    git.refs.tag,
    git.index.base,
    git.index.fun,
    git.index.typ,
)
"""Targets of private aliases in the git module to some modules, not including util."""


_PRIVATE_MODULE_ALIAS_TARGET_NAMES = (
    "git.refs.head",
    "git.refs.log",
    "git.refs.reference",
    "git.refs.symbolic",
    "git.refs.tag",
    "git.index.base",
    "git.index.fun",
    "git.index.typ",
)
"""Expected ``__name__`` attributes of targets of private aliases in the git module."""


def test_alias_target_module_names_are_by_location() -> None:
    """The aliases are weird, but their targets are normal, even in ``__name__``."""
    actual = [module.__name__ for module in _PRIVATE_MODULE_ALIAS_TARGETS]
    expected = list(_PRIVATE_MODULE_ALIAS_TARGET_NAMES)
    assert actual == expected


def test_private_module_alias_access() -> None:
    """Non-util private alias access works but warns and is a deliberate mypy error."""
    with pytest.deprecated_call() as ctx:
        assert (
            git.head,  # type: ignore[attr-defined]
            git.log,  # type: ignore[attr-defined]
            git.reference,  # type: ignore[attr-defined]
            git.symbolic,  # type: ignore[attr-defined]
            git.tag,  # type: ignore[attr-defined]
            git.base,  # type: ignore[attr-defined]
            git.fun,  # type: ignore[attr-defined]
            git.typ,  # type: ignore[attr-defined]
        ) == _PRIVATE_MODULE_ALIAS_TARGETS

    # Each should have warned exactly once, and note what to use instead.
    messages = [str(w.message) for w in ctx]

    assert len(messages) == len(_PRIVATE_MODULE_ALIAS_TARGETS)

    for fullname, message in zip(_PRIVATE_MODULE_ALIAS_TARGET_NAMES, messages):
        assert message.endswith(f"Use {fullname} instead.")


def test_private_module_alias_import() -> None:
    """Non-util private alias import works but warns and is a deliberate mypy error."""
    with pytest.deprecated_call() as ctx:
        from git import head  # type: ignore[attr-defined]
        from git import log  # type: ignore[attr-defined]
        from git import reference  # type: ignore[attr-defined]
        from git import symbolic  # type: ignore[attr-defined]
        from git import tag  # type: ignore[attr-defined]
        from git import base  # type: ignore[attr-defined]
        from git import fun  # type: ignore[attr-defined]
        from git import typ  # type: ignore[attr-defined]

    assert (
        head,
        log,
        reference,
        symbolic,
        tag,
        base,
        fun,
        typ,
    ) == _PRIVATE_MODULE_ALIAS_TARGETS

    # Each import may warn multiple times. In CPython there will be currently always be
    # exactly two warnings per import, possibly due to the equivalent of calling hasattr
    # to do a pre-check prior to retrieving the attribute for actual use. However, for
    # each import, all messages should be the same and should note what to use instead.
    messages_with_duplicates = [str(w.message) for w in ctx]
    messages = [message for message, _ in itertools.groupby(messages_with_duplicates)]

    assert len(messages) == len(_PRIVATE_MODULE_ALIAS_TARGETS)

    for fullname, message in zip(_PRIVATE_MODULE_ALIAS_TARGET_NAMES, messages):
        assert message.endswith(f"Use {fullname} instead.")


def test_dir_contains_public_attributes() -> None:
    """All public attributes of the git module are present when dir() is called on it.

    This is naturally the case, but some ways of adding dynamic attribute access
    behavior can change it, especially if __dir__ is defined but care is not taken to
    preserve the contents that should already be present.

    Note that dir() should usually automatically list non-public attributes if they are
    actually "physically" present as well, so the approach taken here to test it should
    not be reproduced if __dir__ is added (instead, a call to globals() could be used,
    as its keys list the automatic values).
    """
    expected_subset = set(git.__all__)
    actual = set(dir(git))
    assert expected_subset <= actual


def test_dir_does_not_contain_util() -> None:
    """The util attribute is absent from the dir() of git.

    Because this behavior is less confusing than including it, where its meaning would
    be assumed by users examining the dir() for what is available.
    """
    assert "util" not in dir(git)


def test_dir_does_not_contain_private_module_aliases() -> None:
    """Names from inside index and refs only pretend to be there and are not in dir().

    The reason for omitting these is not that they are private, since private members
    are usually included in dir() when actually present. Instead, these are only sort
    of even there, no longer being imported and only being resolved dynamically for the
    time being. In addition, it would be confusing to list these because doing so would
    obscure the module structure of GitPython.
    """
    expected_absent = {
        "head",
        "log",
        "reference",
        "symbolic",
        "tag",
        "base",
        "fun",
        "typ",
    }
    actual = set(dir(git))
    assert not (expected_absent & actual), "They should be completely disjoint."
