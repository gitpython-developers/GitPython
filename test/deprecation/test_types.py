"""Tests for dynamic and static characteristics of git.types module attributes."""

import sys

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

import pytest

import git.types


def test_cannot_access_undefined() -> None:
    """Accessing a bogus attribute in git.types remains a dynamic and static error."""
    with pytest.raises(AttributeError):
        git.types.foo  # type: ignore[attr-defined]


def test_lit_commit_ish() -> None:
    """ """
    # It would be fine to test attribute access rather than a "from" import. But a
    # "from" import is more likely to appear in actual usage, so it is used here.
    with pytest.deprecated_call() as ctx:
        from git.types import Lit_commit_ish

    # As noted in test_toplevel.test_util_alias_import, there may be multiple warnings,
    # but all with the same message.
    (message,) = {str(entry.message) for entry in ctx}
    assert "Lit_commit_ish is deprecated." in message
    assert 'Literal["commit", "tag", "blob", "tree"]' in message, "Has old definition."
    assert 'Literal["commit", "tag"]' in message, "Has new definition."
    assert "GitObjectTypeString" in message, "Has new type name for old definition."

    _: Lit_commit_ish = "commit"  # type: ignore[valid-type]

    # It should be as documented (even though deliberately unusable in static checks).
    assert Lit_commit_ish == Literal["commit", "tag"]
