"""Tests for dynamic and static attribute errors."""

import importlib

import pytest

import git


def test_cannot_get_undefined() -> None:
    with pytest.raises(AttributeError):
        git.foo  # type: ignore[attr-defined]


def test_cannot_import_undefined() -> None:
    with pytest.raises(ImportError):
        from git import foo  # type: ignore[attr-defined]  # noqa: F401


def test_util_alias_access_resolves() -> None:
    """These resolve for now, though they're private and we do not guarantee this."""
    assert git.util is git.index.util


def test_util_alias_import_resolves() -> None:
    from git import util

    assert util is git.index.util


def test_util_alias_access_warns() -> None:
    with pytest.deprecated_call() as ctx:
        git.util

    assert len(ctx) == 1
    message = ctx[0].message.args[0]
    assert "git.util" in message
    assert "git.index.util" in message
    assert "should not be relied on" in message


def test_util_alias_import_warns() -> None:
    with pytest.deprecated_call() as ctx:
        from git import util  # noqa: F401

    message = ctx[0].message.args[0]
    assert "git.util" in message
    assert "git.index.util" in message
    assert "should not be relied on" in message


def test_private_module_aliases() -> None:
    """These exist dynamically (for now) but mypy treats them as absent (intentionally).

    This code verifies the effect of static type checking when analyzed by mypy, if mypy
    is configured with ``warn_unused_ignores = true``.

    More detailed dynamic behavior is examined in the subsequent test cases.
    """
    git.head  # type: ignore[attr-defined]
    git.log  # type: ignore[attr-defined]
    git.reference  # type: ignore[attr-defined]
    git.symbolic  # type: ignore[attr-defined]
    git.tag  # type: ignore[attr-defined]
    git.base  # type: ignore[attr-defined]
    git.fun  # type: ignore[attr-defined]
    git.typ  # type: ignore[attr-defined]


_parametrize_by_private_alias = pytest.mark.parametrize(
    "name, fullname",
    [
        ("head", "git.refs.head"),
        ("log", "git.refs.log"),
        ("reference", "git.refs.reference"),
        ("symbolic", "git.refs.symbolic"),
        ("tag", "git.refs.tag"),
        ("base", "git.index.base"),
        ("fun", "git.index.fun"),
        ("typ", "git.index.typ"),
    ],
)


@_parametrize_by_private_alias
def test_private_module_alias_access_resolves(name: str, fullname: str) -> None:
    """These resolve for now, though they're private we do not guarantee this."""
    assert getattr(git, name) is importlib.import_module(fullname)


@_parametrize_by_private_alias
def test_private_module_alias_import_resolves(name: str, fullname: str) -> None:
    exec(f"from git import {name}")
    assert locals()[name] is importlib.import_module(fullname)


@_parametrize_by_private_alias
def test_private_module_alias_access_warns(name: str, fullname: str) -> None:
    with pytest.deprecated_call() as ctx:
        getattr(git, name)

    assert len(ctx) == 1
    assert ctx[0].message.args[0].endswith(f"Use {fullname} instead.")


@_parametrize_by_private_alias
def test_private_module_alias_import_warns(name: str, fullname: str) -> None:
    with pytest.deprecated_call() as ctx:
        exec(f"from git import {name}")

    assert ctx[0].message.args[0].endswith(f"Use {fullname} instead.")
