"""Tests for dynamic and static attribute errors in GitPython's top-level git module.

Provided mypy has ``warn_unused_ignores = true`` set, running mypy on these test cases
checks static typing of the code under test. (Running pytest checks dynamic behavior.)
"""

from itertools import groupby
from typing import Type

import pytest
from typing_extensions import assert_type

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
    """Accessing a bogus attribute in git remains both a dynamic and static error."""
    with pytest.raises(AttributeError):
        git.foo  # type: ignore[attr-defined]


def test_cannot_import_undefined() -> None:
    """Importing a bogus attribute from git remains both a dynamic and static error."""
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
    assert "git.util" in message
    assert "git.index.util" in message
    assert "should not be relied on" in message

    # As above, we check access through the util alias to the TemporaryFileSwap member.
    from git.index.util import TemporaryFileSwap

    assert_type(util.TemporaryFileSwap, Type[TemporaryFileSwap])

    # This comes after the static assertion, just in case it would affect the inference.
    assert util.TemporaryFileSwap is TemporaryFileSwap


# Split out util and have all its tests be separate, above.
_MODULE_ALIAS_TARGETS = (
    git.refs.head,
    git.refs.log,
    git.refs.reference,
    git.refs.symbolic,
    git.refs.tag,
    git.index.base,
    git.index.fun,
    git.index.typ,
)


def test_private_module_alias_access() -> None:
    """Non-util private alias access works, warns, but is a deliberate mypy error."""
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
        ) == _MODULE_ALIAS_TARGETS

    # Each should have warned exactly once, and note what to use instead.
    messages = [str(w.message) for w in ctx]
    for target, message in zip(_MODULE_ALIAS_TARGETS, messages, strict=True):
        assert message.endswith(f"Use {target.__name__} instead.")


def test_private_module_alias_import() -> None:
    """Non-util private alias access works, warns, but is a deliberate mypy error."""
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
    ) == _MODULE_ALIAS_TARGETS

    # Each import may warn multiple times. In CPython there will be currently always be
    # exactly two warnings per import, possibly due to the equivalent of calling hasattr
    # to do a pre-check prior to retrieving the attribute for actual use. However, for
    # each import, all messages should be the same and should note what to use instead.
    messages_with_duplicates = [str(w.message) for w in ctx]
    messages = [message for message, _ in groupby(messages_with_duplicates)]
    for target, message in zip(_MODULE_ALIAS_TARGETS, messages, strict=True):
        assert message.endswith(f"Use {target.__name__} instead.")
