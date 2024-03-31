# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests for dynamic and static characteristics of git.compat module attributes.

These tests verify that the is_<platform> attributes are available, and are even listed
in the output of dir(), but issue warnings, and that bogus (misspelled or unrecognized)
attribute access is still an error both at runtime and with mypy. This is similar to
some of the tests in test_toplevel, but the situation being tested here is simpler
because it does not involve unintuitive module aliasing or import behavior. So this only
tests attribute access, not "from" imports (whose behavior can be intuitively inferred).
"""

import os
import sys

if sys.version_info >= (3, 11):
    from typing import assert_type
else:
    from typing_extensions import assert_type

import pytest

import git.compat

_MESSAGE_LEADER = "{} and other is_<platform> aliases are deprecated."
"""Form taken by the beginning of the warnings issued for is_<platform> access."""


def test_cannot_access_undefined() -> None:
    """Accessing a bogus attribute in git.compat remains a dynamic and static error."""
    with pytest.raises(AttributeError):
        git.compat.foo  # type: ignore[attr-defined]


def test_is_platform() -> None:
    """The is_<platform> attributes work, warn, and mypy accepts code accessing them."""
    fully_qualified_names = [
        "git.compat.is_win",
        "git.compat.is_posix",
        "git.compat.is_darwin",
    ]

    with pytest.deprecated_call() as ctx:
        is_win = git.compat.is_win
        is_posix = git.compat.is_posix
        is_darwin = git.compat.is_darwin

    assert_type(is_win, bool)
    assert_type(is_posix, bool)
    assert_type(is_darwin, bool)

    messages = [str(entry.message) for entry in ctx]
    assert len(messages) == 3

    for fullname, message in zip(fully_qualified_names, messages):
        assert message.startswith(_MESSAGE_LEADER.format(fullname))

    # These assertions exactly reproduce the expressions in the code under test, so they
    # are not good for testing that the values are correct. Instead, their purpose is to
    # ensure that any dynamic machinery put in place in git.compat to cause warnings to
    # be issued does not get in the way of the intended values being accessed.
    assert is_win == (os.name == "nt")
    assert is_posix == (os.name == "posix")
    assert is_darwin == (sys.platform == "darwin")


def test_dir() -> None:
    """dir() on git.compat includes all public attributes, even if deprecated.

    As dir() usually does, it also has nonpublic attributes, which should also not be
    removed by a custom __dir__ function, but those are less important to test.
    """
    expected_subset = {
        "is_win",
        "is_posix",
        "is_darwin",
        "defenc",
        "safe_decode",
        "safe_encode",
        "win_encode",
    }
    actual = set(dir(git.compat))
    assert expected_subset <= actual
