"""Tests for dynamic and static errors and warnings in GitPython's git.compat module.

These tests verify that the is_<platform> aliases are available, and are even listed in
the output of dir(), but issue warnings, and that bogus (misspelled or unrecognized)
attribute access is still an error both at runtime and with mypy. This is similar to
some of the tests in test_toplevel, but the situation being tested here is simpler
because it does not involve unintuitive module aliasing or import behavior. So this only
tests attribute access, not "from" imports (whose behavior can be intuitively inferred).
"""

import os
import sys

import pytest

import git.compat


_MESSAGE_LEADER = "{} and other is_<platform> aliases are deprecated."


def test_cannot_access_undefined() -> None:
    """Accessing a bogus attribute in git.compat remains a dynamic and static error."""
    with pytest.raises(AttributeError):
        git.compat.foo  # type: ignore[attr-defined]


def test_is_win() -> None:
    with pytest.deprecated_call() as ctx:
        value = git.compat.is_win
    (message,) = [str(entry.message) for entry in ctx]  # Exactly one message.
    assert message.startswith(_MESSAGE_LEADER.format("git.compat.is_win"))
    assert value == (os.name == "nt")
