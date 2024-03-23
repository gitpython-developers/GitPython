"""Tests for dynamic and static attribute errors in GitPython's top-level git module.

Provided mypy has ``warn_unused_ignores = true`` set, running mypy on these test cases
checks static typing of the code under test. (Running pytest checks dynamic behavior.)
"""

import importlib
from typing import Type

import pytest

import git


def test_cannot_get_undefined() -> None:
    with pytest.raises(AttributeError):
        git.foo  # type: ignore[attr-defined]


def test_cannot_import_undefined() -> None:
    with pytest.raises(ImportError):
        from git import foo  # type: ignore[attr-defined]  # noqa: F401


def test_util_alias_members_resolve() -> None:
    """git.index.util members can be accessed via git.util, and mypy recognizes it."""
    gu_tfs = git.util.TemporaryFileSwap
    from git.index.util import TemporaryFileSwap

    def accepts_tfs_type(t: Type[TemporaryFileSwap]) -> None:
        pass

    def rejects_tfs_type(t: Type[git.Git]) -> None:
        pass

    # TODO: When typing_extensions is made a test dependency, use assert_type for this.
    accepts_tfs_type(gu_tfs)
    rejects_tfs_type(gu_tfs)  # type: ignore[arg-type]

    assert gu_tfs is TemporaryFileSwap


def test_util_alias_access_warns() -> None:
    with pytest.deprecated_call() as ctx:
        git.util

    assert len(ctx) == 1
    message = str(ctx[0].message)
    assert "git.util" in message
    assert "git.index.util" in message
    assert "should not be relied on" in message


def test_util_alias_import_warns() -> None:
    with pytest.deprecated_call() as ctx:
        from git import util  # noqa: F401

    message = str(ctx[0].message)
    assert "git.util" in message
    assert "git.index.util" in message
    assert "should not be relied on" in message


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
    git.index.util,
)


def test_private_module_alias_access_on_git_module() -> None:
    """Private alias access works, warns, and except for util is a mypy error."""
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
            git.util,
        ) == _MODULE_ALIAS_TARGETS

    messages = [str(w.message) for w in ctx]
    for target, message in zip(_MODULE_ALIAS_TARGETS[:-1], messages[:-1], strict=True):
        assert message.endswith(f"Use {target.__name__} instead.")

    util_message = messages[-1]
    assert "git.util" in util_message
    assert "git.index.util" in util_message
    assert "should not be relied on" in util_message


def test_private_module_alias_import_from_git_module() -> None:
    """Private alias import works, warns, and except for util is a mypy error."""
    with pytest.deprecated_call() as ctx:
        from git import head  # type: ignore[attr-defined]
        from git import log  # type: ignore[attr-defined]
        from git import reference  # type: ignore[attr-defined]
        from git import symbolic  # type: ignore[attr-defined]
        from git import tag  # type: ignore[attr-defined]
        from git import base  # type: ignore[attr-defined]
        from git import fun  # type: ignore[attr-defined]
        from git import typ  # type: ignore[attr-defined]
        from git import util

    assert (
        head,
        log,
        reference,
        symbolic,
        tag,
        base,
        fun,
        typ,
        util,
    ) == _MODULE_ALIAS_TARGETS

    # FIXME: This fails because, with imports, multiple consecutive accesses may occur.
    # In practice, with CPython, it is always exactly two accesses, the first from the
    # equivalent of a hasattr, and the second to fetch the attribute intentionally.
    messages = [str(w.message) for w in ctx]
    for target, message in zip(_MODULE_ALIAS_TARGETS[:-1], messages[:-1], strict=True):
        assert message.endswith(f"Use {target.__name__} instead.")

    util_message = messages[-1]
    assert "git.util" in util_message
    assert "git.index.util" in util_message
    assert "should not be relied on" in util_message
