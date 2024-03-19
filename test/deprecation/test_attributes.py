"""Tests for dynamic and static attribute errors."""

import pytest


def test_cannot_get_undefined() -> None:
    import git

    with pytest.raises(AttributeError):
        git.foo


def test_cannot_import_undefined() -> None:
    with pytest.raises(ImportError):
        from git import foo
